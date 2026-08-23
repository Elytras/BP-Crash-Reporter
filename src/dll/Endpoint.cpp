#include "Endpoint.h"

#include <array>
#include <cstring>
#include <format>

#include "Platform.h"
#include "Symbols.h"

using namespace bpc;
using namespace bpc::ue;
namespace plat = bpc::plat;

namespace
{
    endpoint::Resolved g_r;
    /* Seeded, not empty: the pre-wait report in DllMain is written before the first TryInit,
       and a bare "--- endpoint self-test ---" header with nothing under it reads as a bug in
       the report rather than as the honest "we have not looked yet" that it is. */
    std::string        g_report = "  (not attempted yet -- still in startup)\n";
    bool               g_ready = false;

    /* Consecutive attempts where the object array was healthy but ProcessInternal would not
       resolve. Only a sustained failure against a populated array is evidence of a broken scan
       rather than an engine still starting, so the reject verdict waits for both. */
    unsigned           g_piFailures = 0;
    constexpr unsigned kRejectAfter    = 240;     // ~60s at the caller's 250ms pacing
    constexpr int32_t  kHealthyObjects = 10000;   // a booted UE game is far past this

    void Say(const char* what, bool ok, const std::string& detail)
    {
        g_report += std::format("  [{}] {:<16} {}\n", ok ? '+' : '!', what, detail);
    }

    /* When symbols are available the self-test can name what a resolution landed on, which is
       the only way to tell a found address from the correct one without crashing first. */
    std::string SymNote(const void* p)
    {
        char b[512];
        if (!p || !sym::Resolve(p, b, sizeof(b)) || !::strchr(b, '!')) return {};
        return std::format("  == {}", b);
    }

    /*
    GObjects, ported from Dumper-7 (Dumper/Engine/Private/Unreal/ObjectArray.cpp).

    Instead of a byte signature, we scan the writable data sections for an address whose fields
    read back as a self-consistent FUObjectArray. Since it matches the array's shape rather than
    the code that touches it, it needs no per-game signature and survives a recompile.
    */

    struct ChunkedLayout { int objects, maxElements, numElements, maxChunks, numChunks; };
    struct FixedLayout   { int objects, maxObjects, numObjects; };

    constexpr std::array kChunkedLayouts = {
        ChunkedLayout{ 0x00, 0x10, 0x14, 0x18, 0x1C },   // default UE4.21 .. UE5.x
        ChunkedLayout{ 0x10, 0x00, 0x04, 0x08, 0x0C },   // Back4Blood
        ChunkedLayout{ 0x18, 0x10, 0x00, 0x14, 0x20 },   // Multiversus
        ChunkedLayout{ 0x18, 0x00, 0x14, 0x10, 0x04 },   // MindsEye
    };
    constexpr FixedLayout kFixedLayout{ 0x00, 0x08, 0x0C };   // UE4.11 .. UE4.20

    struct ArrayInfo
    {
        bool          chunked = false;
        ChunkedLayout chunkedLayout{};
        FixedLayout   fixedLayout{};
        int32_t       perChunk = 0;
        uint32_t      itemSize = 24;      // FUObjectItem stride
        uint32_t      itemObjOff = 0;     // offset of Object* inside FUObjectItem
    };
    ArrayInfo g_arr;

    template <class T> T Read(const uint8_t* p, int off) { return *reinterpret_cast<const T*>(p + off); }

    bool ValidChunked(const uint8_t* a, const ChunkedLayout& L)
    {
        if (plat::BadRead(a, 0x28)) return false;
        void** chunks = Read<void**>(a, L.objects);
        const int32_t maxEl = Read<int32_t>(a, L.maxElements);
        const int32_t numEl = Read<int32_t>(a, L.numElements);
        const int32_t maxCh = Read<int32_t>(a, L.maxChunks);
        const int32_t numCh = Read<int32_t>(a, L.numChunks);

        if (numCh > 0x14 || numCh < 1) return false;
        if (maxCh > 0x5FF || maxCh < 6) return false;
        if (numEl <= 0x800 || maxEl <= 0x10000) return false;
        if (numEl > maxEl || numCh > maxCh) return false;
        if (maxEl % 0x10) return false;

        const int32_t perChunk = maxEl / maxCh;
        if (perChunk % 0x10) return false;
        if (perChunk < 0x8000 || perChunk > 0x80000) return false;
        if ((numEl / perChunk) + 1 != numCh) return false;
        if (maxEl / perChunk != maxCh) return false;
        if (!chunks || plat::BadRead(chunks, numCh * sizeof(void*))) return false;
        for (int i = 0; i < numCh; ++i)
            if (!chunks[i] || plat::BadRead(chunks[i])) return false;
        return true;
    }

    bool ValidFixed(const uint8_t* a, const FixedLayout& L)
    {
        if (plat::BadRead(a, 0x10)) return false;
        uint8_t* objects = Read<uint8_t*>(a, L.objects);
        const int32_t maxEl = Read<int32_t>(a, L.maxObjects);
        const int32_t numEl = Read<int32_t>(a, L.numObjects);
        if (numEl > maxEl || maxEl > 0x400000 || numEl < 0x1000) return false;
        if (plat::BadRead(objects, 0x80)) return false;

        // Item 5 must know it is item 5: UObject::InternalIndex sits at +0x0C.
        auto* fifth = *reinterpret_cast<UObject**>(objects + 5 * 24);
        if (plat::BadRead(fifth, sizeof(UObject))) return false;
        return fifth->Index == 5;
    }

    /* FUObjectItem stride and offset probe, also from Dumper-7. The first item's Object* is the
       first readable pointer, and the stride is the step at which the next two entries are also
       readable object pointers. */
    void ProbeItemLayout(const uint8_t* firstItem)
    {
        for (int i = 0; i < 0x20; i += 4)
            if (!plat::BadRead(*reinterpret_cast<void* const*>(firstItem + i)))
            {
                g_arr.itemObjOff = static_cast<uint32_t>(i);
                break;
            }
        for (int i = static_cast<int>(g_arr.itemObjOff) + 8; i <= 0x38; i += 4)
        {
            void* second = *reinterpret_cast<void* const*>(firstItem + i);
            void* third = *reinterpret_cast<void* const*>(firstItem + (i * 2) - g_arr.itemObjOff);
            if (!plat::BadRead(second) && !plat::BadRead(*reinterpret_cast<void**>(second)) &&
                !plat::BadRead(third) && !plat::BadRead(*reinterpret_cast<void**>(third)))
            {
                g_arr.itemSize = static_cast<uint32_t>(i) - g_arr.itemObjOff;
                return;
            }
        }
    }

    bool FindGObjects()
    {
        const uint8_t* found = nullptr;
        // Writable, non-discardable data sections, at the 4-byte granularity Dumper-7 uses.
        plat::ForEachSection([&](plat::Section s)
        {
            if (s.size < 0x40) return true;
            for (const uint8_t* a = s.start; a + 0x40 < s.start + s.size; a += 4)
            {
                for (const auto& L : kChunkedLayouts)
                    if (ValidChunked(a, L))
                    {
                        g_arr.chunked = true; g_arr.chunkedLayout = L; found = a; return false;
                    }
                if (ValidFixed(a, kFixedLayout))
                {
                    g_arr.chunked = false; g_arr.fixedLayout = kFixedLayout; found = a; return false;
                }
            }
            return true;
        }, plat::SectionKind::Writable);

        if (!found) return false;
        g_r.gObjects = const_cast<uint8_t*>(found);

        if (g_arr.chunked)
        {
            const auto& L = g_arr.chunkedLayout;
            g_arr.perChunk = Read<int32_t>(found, L.maxElements) / Read<int32_t>(found, L.maxChunks);
            uint8_t** chunks = Read<uint8_t**>(found, L.objects);
            ProbeItemLayout(chunks[0]);
        }
        else
        {
            ProbeItemLayout(Read<uint8_t*>(found, g_arr.fixedLayout.objects));
        }
        return true;
    }

    /*
    FNamePool, from Dumper-7's TryFindNamePool_Windows, trimmed to the FNamePool (UE4.23+) case.

    We look for a `lea rcx, [pool]; call FNamePool::FNamePool` pair, then confirm the callee is
    really the pool constructor by the two things only it does: initialise an SRW lock, and
    reference the literal "ByteProperty" while pre-interning the hardcoded type names.
    */

    const void* FindStringRef(const uint8_t* from, size_t range, const wchar_t* wide, const char* narrow)
    {
        const size_t wlen = ::wcslen(wide) * sizeof(wchar_t);
        const size_t nlen = ::strlen(narrow);
        // Any `lea reg, [rip+d]` inside the window whose target is the literal.
        for (size_t i = 0; i + 7 <= range; ++i)
        {
            if (from[i] != 0x48 && from[i] != 0x4C) continue;
            if (from[i + 1] != 0x8D) continue;
            const uintptr_t t = plat::RipTarget(from + i, 3, 7);
            if (plat::BadRead(reinterpret_cast<const void*>(t), wlen)) continue;
            if (::memcmp(reinterpret_cast<const void*>(t), wide, wlen) == 0) return reinterpret_cast<const void*>(t);
            if (!plat::BadRead(reinterpret_cast<const void*>(t), nlen) &&
                ::memcmp(reinterpret_cast<const void*>(t), narrow, nlen) == 0) return reinterpret_cast<const void*>(t);
        }
        return nullptr;
    }

    bool FindNamePool()
    {
        const auto initSrw = reinterpret_cast<uintptr_t>(plat::ImportedFunction(L"kernel32.dll", "InitializeSRWLock"));
        const auto rtlInitSrw = reinterpret_cast<uintptr_t>(plat::ImportedFunction(L"ntdll.dll", "RtlInitializeSRWLock"));

        const uint8_t* at = nullptr;
        while ((at = plat::FindPattern("48 8D 0D ? ? ? ? E8", at)) != nullptr)
        {
            const uintptr_t ctor = plat::CallTarget(at + 7);
            if (!ctor || !plat::InModule(reinterpret_cast<void*>(ctor))) continue;
            const auto* body = reinterpret_cast<const uint8_t*>(ctor);
            if (plat::BadRead(body, 0x50)) continue;

            for (int i = 0; i < 0x50; ++i)
            {
                if (body[i] != 0xFF || body[i + 1] != 0x15) continue;   // call [rip+d]
                const uintptr_t slot = plat::IndirectCallSlot(body + i);
                if (plat::BadRead(reinterpret_cast<void*>(slot))) continue;
                const uintptr_t target = *reinterpret_cast<uintptr_t*>(slot);
                if (target != initSrw && target != rtlInitSrw) continue;
                if (!FindStringRef(body, 0x2A0, L"ByteProperty", "ByteProperty")) continue;

                g_r.namePool = reinterpret_cast<uint8_t*>(plat::RipTarget(at, 3, 7));
                return !plat::BadRead(g_r.namePool, 0x20);
            }
        }
        return false;
    }

    /*
    ProcessEvent, via Dumper-7's vtable walk. It is the only UObject virtual that tests both
    FUNC_Native (0x400) and 0x400000 against UFunction::FunctionFlags at +0xB0. The test encodes
    as `F7 /r disp32 imm32`, with the modrm byte wildcarded so the base register does not matter.
    */

    bool LooksLikeProcessEvent(const uint8_t* fn)
    {
        static constexpr int kNative[] = { 0xF7, -1, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00 };
        static constexpr int kOther[] = { 0xF7, -1, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00 };
        return plat::FindBytesInRange(kNative, 10, fn, 0x400)
            && plat::FindBytesInRange(kOther, 10, fn, 0xF00);
    }

    bool FindProcessEvent()
    {
        UObject* any = endpoint::ObjectByIndex(0);
        if (!any || plat::BadRead(any->VTable)) return false;
        void** vft = reinterpret_cast<void**>(any->VTable);

        const int idx = plat::IterateVTable(vft, [](const uint8_t* fn, int) { return LooksLikeProcessEvent(fn); });
        if (idx < 0) return false;
        g_r.processEventIdx = idx;
        g_r.processEvent = vft[idx];
        return true;
    }

    /*
    ProcessInternal needs no signature at all. UFunction::Bind sets a pure-scripted function's
    ExecFunction to &UObject::ProcessInternal, so any UFunction that is non-native and carries
    bytecode hands us the address. This holds in both the UE4.27 and UE5.6 sources.
    */
    bool FindProcessInternal()
    {
        const int32_t n = endpoint::NumObjects();
        for (int32_t i = 0; i < n; ++i)
        {
            UObject* o = endpoint::ObjectByIndex(i);
            if (!IsValid(o) || !IsA(o, CAST_UFunction)) continue;
            auto* fn = static_cast<UFunction*>(o);
            if (fn->FunctionFlags & FUNC_Native) continue;
            if (fn->ScriptNum <= 0 || !fn->ScriptData) continue;
            if (!fn->ExecFunction || !plat::InModule(reinterpret_cast<void*>(fn->ExecFunction))) continue;
            g_r.processInternal = reinterpret_cast<void*>(fn->ExecFunction);
            return true;
        }
        return false;
    }
}

namespace
{
    /*
    ProcessLocalScriptFunction, the interpreter loop every scripted function body runs inside.

    We find it by decoding ProcessInternal, which in a shipping build is barely more than a
    forwarder:

        void UObject::ProcessInternal(UObject* Context, FFrame& Stack, RESULT_DECL)
        {
            if (Context->IsPendingKill()) ...
            ProcessLocalScriptFunction(Context, Stack, RESULT_PARAM);   // often a tail call
        }

    So we collect every distinct in-module `call rel32` / `jmp rel32` target up to the first `ret`
    and accept the answer only if there is exactly one. On ambiguity we return nothing rather than
    guess, because a wrong target here would not just mislabel a frame: it would detour an
    arbitrary function and reinterpret its arguments as (UObject*, FFrame&, void*).

    A lookup by name would be better but rarely works. The generated PDBs these games use carry an
    address-to-name map with no name index, so SymFromAddr resolves while SymFromName returns
    ERROR_NOT_FOUND. We still try AddressOf first, for the case where a fully indexed PDB is there.
    */
    /*
    `candidates` reports how many direct calls the forwarder actually held, so the self-test can
    say WHY a byte-decoded answer is or isn't trustworthy instead of only that one was found.
    */
    void* FindProcessLocal(int& candidates)
    {
        candidates = 0;
        if (const void* byName = sym::AddressOf("ProcessLocalScriptFunction"))
            return const_cast<void*>(byName);

        const auto* body = static_cast<const uint8_t*>(g_r.processInternal);
        if (!body || plat::BadRead(body, 0x100)) return nullptr;

        void* found = nullptr;
        for (int i = 0; i < 0x100; ++i)
        {
            if (body[i] == 0xC3) break;                       // end of the forwarder
            if (body[i] != 0xE8 && body[i] != 0xE9) continue; // call rel32 / jmp rel32

            const uintptr_t t = plat::RipTarget(body + i, 1, 5);
            if (!t || !plat::InModule(reinterpret_cast<void*>(t))) continue;
            if (reinterpret_cast<void*>(t) == g_r.processInternal) continue;

            /*
            FIRST direct call wins; a second one is not ambiguity. ProcessInternal forwards to
            ProcessLocalScriptFunction on its main path and only then branches off to colder
            helpers, so requiring a unique call target rejected every real build that had one --
            which is exactly how the BP-to-BP frames went missing while the address sat right
            there in the first call.
            */
            ++candidates;
            if (!found) found = reinterpret_cast<void*>(t);
        }
        return found;
    }
}

// Object array access.

int32_t endpoint::NumObjects()
{
    if (!g_r.gObjects) return 0;
    const int off = g_arr.chunked ? g_arr.chunkedLayout.numElements : g_arr.fixedLayout.numObjects;
    return Read<int32_t>(g_r.gObjects, off);
}

UObject* endpoint::ObjectByIndex(int32_t i)
{
    if (!g_r.gObjects || i < 0 || i >= NumObjects()) return nullptr;

    if (!g_arr.chunked)
    {
        auto* items = Read<uint8_t*>(g_r.gObjects, g_arr.fixedLayout.objects);
        if (!items) return nullptr;
        return *reinterpret_cast<UObject**>(items + i * g_arr.itemSize + g_arr.itemObjOff);
    }
    auto** chunks = Read<uint8_t**>(g_r.gObjects, g_arr.chunkedLayout.objects);
    if (!chunks || g_arr.perChunk <= 0) return nullptr;
    uint8_t* chunk = chunks[i / g_arr.perChunk];
    if (!chunk) return nullptr;
    return *reinterpret_cast<UObject**>(chunk + (i % g_arr.perChunk) * g_arr.itemSize + g_arr.itemObjOff);
}

// Init.

endpoint::Progress endpoint::TryInit()
{
    if (g_ready) return Progress::Ready;

    /* Rebuilt every attempt, so the self-test in any report always describes the LATEST attempt
       rather than whatever the first one happened to see. */
    g_report = std::format("endpoint: module base 0x{:X}, size 0x{:X}\n",
        reinterpret_cast<uintptr_t>(plat::ModuleBase()), plat::ModuleSize());

    /* GObjects comes first, because every other resolution depends on it. Injection can land long
       before the engine builds the array -- that is NotYet, not a failure. */
    if (!FindGObjects())
    {
        Say("GObjects", false, "not built yet -- the engine has not created its object array");
        return Progress::NotYet;
    }

    const int32_t objects = NumObjects();
    Say("GObjects", true, std::format("+0x{:X} ({}, {} objects, item stride {})",
        plat::Rva(g_r.gObjects), g_arr.chunked ? "chunked" : "fixed", objects, g_arr.itemSize));

    const bool pool = FindNamePool();
    Say("FNamePool", pool, pool ? std::format("+0x{:X}", plat::Rva(g_r.namePool))
                                : "not found; names will read as <name?>");

    const bool pe = FindProcessEvent();
    Say("ProcessEvent", pe, pe ? std::format("+0x{:X} (vtable index {}){}",
                                    plat::Rva(g_r.processEvent), g_r.processEventIdx, SymNote(g_r.processEvent))
                               : "not found; native frames will be missing from the stack");

    const bool pi = FindProcessInternal();
    if (!pi)
    {
        ++g_piFailures;

        /* The verdict the caller cannot reach on its own. A populated object array means the
           engine is up and Blueprint classes are loaded, so a ProcessInternal that still will not
           resolve after a minute of that is our scan being wrong -- report it and stop, rather
           than spinning silently forever. Anything short of that is still "the game is starting". */
        if (objects >= kHealthyObjects && g_piFailures >= kRejectAfter)
        {
            Say("ProcessInternal", false, std::format(
                "NOT RESOLVABLE after {} attempts against {} live objects -- the engine is up, so "
                "this scan is broken on this build", g_piFailures, objects));
            return Progress::Rejected;
        }

        Say("ProcessInternal", false, std::format(
            "not resolved yet (attempt {}, {} objects); still waiting", g_piFailures, objects));
        return Progress::NotYet;
    }

    Say("ProcessInternal", true, std::format("+0x{:X}{}",
        plat::Rva(g_r.processInternal), SymNote(g_r.processInternal)));

    int candidates = 0;
    g_r.processLocal = FindProcessLocal(candidates);
    Say("ProcessLocal", g_r.processLocal != nullptr,
        g_r.processLocal
            ? std::format("+0x{:X}{}{}", plat::Rva(g_r.processLocal), SymNote(g_r.processLocal),
                candidates ? std::format(" (first of {} direct calls in the forwarder)", candidates)
                           : std::string(" (by symbol name)"))
            : "not found; BP-to-BP frames will be missing from the stack");

    // ProcessInternal is the only hard requirement; it alone produces the Blueprint call stack.
    g_ready = true;
    return Progress::Ready;
}

bool                      endpoint::Ready() { return g_ready; }
const endpoint::Resolved& endpoint::Get() { return g_r; }
const std::string&        endpoint::Report() { return g_report; }
