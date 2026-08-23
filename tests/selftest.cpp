/*
selftest.cpp

The one check that runs without a game. Most of the tool needs a live UE process, but the pure
decoders do not: the pattern scanner, the FName pool reader, the opcode table, and the dbghelp
path. All of them are hand-rolled and all of them fail silently if they drift, and a synthetic
name pool is enough to catch that.

  cmake --build build --config Release --target selftest && build/Release/selftest.exe
*/

#include <cstdio>
#include <cstring>

#include "../src/dll/Bytecode.h"
#include "../src/dll/NamePool.h"
#include "../src/dll/Platform.h"
#include "../src/dll/Symbols.h"
#include "../src/dll/Ue.h"

using namespace bpc;

/* We do not use assert() here, because this builds in Release, where NDEBUG compiles the checks
   and the calls inside them out of existence and leaves a test that passes by doing nothing. */
static int g_fails = 0;

static bool Check(bool cond, const char* expr, int line)
{
    if (!cond) { std::printf("FAIL selftest.cpp:%d  %s\n", line, expr); ++g_fails; }
    return cond;
}
#define CHECK(expr) Check(!!(expr), #expr, __LINE__)

namespace
{
    alignas(16) uint8_t g_block[4096];

    /* A stand-in FNameEntryAllocator, laid out like the engine's so the reader runs against its
       real offsets rather than hand-set globals:
         +0x08 CurrentBlock (read live on every lookup)   +0x10 Blocks[] */
    alignas(16) uint8_t g_pool[0x40];

    // Write an FNameEntry at `off` (in entry-stride units of 2 bytes) and return that offset.
    uint32_t PutName(uint32_t off, const char* text)
    {
        const uint16_t len = static_cast<uint16_t>(::strlen(text));
        uint8_t* e = g_block + static_cast<size_t>(off) * 2;
        *reinterpret_cast<uint16_t*>(e) = static_cast<uint16_t>(len << 6);   // bit0 = wide, clear
        ::memcpy(e + 2, text, len);
        return off;
    }

    void TestNames()
    {
        *reinterpret_cast<uint32_t*>(g_pool + 0x08) = 0;                   // CurrentBlock
        *reinterpret_cast<uint8_t**>(g_pool + 0x10) = g_block;             // Blocks[0]
        names::g_pool = g_pool;
        names::g_blocks = reinterpret_cast<uint8_t**>(g_pool + 0x10);
        names::g_blockCount = 0;
        names::g_ok = true;

        const uint32_t none = PutName(0, "None");
        const uint32_t foo = PutName(8, "Foo");

        char out[64];
        names::Decode({ static_cast<int32_t>(none), 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "None") == 0);

        names::Decode({ static_cast<int32_t>(foo), 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "Foo") == 0);

        // FName.Number is 1-based on the wire, so Number 4 renders as _3.
        names::Decode({ static_cast<int32_t>(foo), 4 }, out, sizeof(out));
        CHECK(::strcmp(out, "Foo_3") == 0);

        // A block index past the live CurrentBlock must degrade, and say which index failed.
        names::Decode({ 0x7F000000, 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "<name?#7F000000>") == 0);

        /* This is what guards the live-count read: a name in a block allocated after bind time
           has to resolve, because the pool grows for the whole session. */
        *reinterpret_cast<uint8_t**>(g_pool + 0x18) = g_block;             // Blocks[1]
        *reinterpret_cast<uint32_t*>(g_pool + 0x08) = 1;                   // CurrentBlock grew
        names::Decode({ static_cast<int32_t>((1u << 16) | foo), 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "Foo") == 0);

        std::printf("names   ok\n");
    }

    void TestPattern()
    {
        const uint8_t hay[] = { 0x90, 0x48, 0x8D, 0x0D, 0x11, 0x22, 0x33, 0x44, 0xE8, 0x90 };

        plat::PatternByte pat[8];
        CHECK(plat::ParsePattern("48 8D 0D ? ? ? ? E8", pat, 8) == 8);
        CHECK(pat[0].value == 0x48 && !pat[0].wild);
        CHECK(pat[3].wild);
        CHECK(plat::ParsePattern("48 ZZ", pat, 8) == 0);          // malformed
        CHECK(plat::ParsePattern("48 8D 0D", pat, 2) == 0);       // exceeds capacity

        const uint8_t* hit = plat::FindPatternIn(hay, sizeof(hay), "48 8D 0D ? ? ? ? E8");
        CHECK(hit == hay + 1);
        CHECK(plat::FindPatternIn(hay, sizeof(hay), "48 8D 0E") == nullptr);

        // rip-relative: lea is 7 bytes, disp32 at +3.
        CHECK(plat::RipTarget(hit, 3, 7) == reinterpret_cast<uintptr_t>(hit) + 7 + 0x44332211);

        CHECK(plat::BadRead(nullptr));
        CHECK(!plat::BadRead(hay, sizeof(hay)));

        std::printf("pattern ok\n");
    }

    void TestBytecode()
    {
        char out[128];
        const uint8_t nothing = 0x0B;
        bytecode::Describe(&nothing, out, sizeof(out));
        CHECK(::strcmp(out, "EX_Nothing") == 0);

        const uint8_t unknown = 0x77;
        bytecode::Describe(&unknown, out, sizeof(out));
        CHECK(::strcmp(out, "EX_?") == 0);

        bytecode::Describe(nullptr, out, sizeof(out));
        CHECK(::strcmp(out, "<code?>") == 0);

        std::printf("opcode  ok\n");
    }

    /* Symbolication against this exe's own PDB. Covers the whole dbghelp path end to end: dynamic
       load, SymInitialize, module attribution and name lookup, with no game involved. */
    void TestSymbols()
    {
        char out[512];

        CHECK(!sym::Resolve(nullptr, out, sizeof(out)));
        int onTheStack = 0;
        CHECK(!sym::Resolve(&onTheStack, out, sizeof(out)));   // the stack is in no module

        const bool ready = sym::Init();
        std::printf("symbols %s\n  status: %s\n", ready ? "ok" : "off", sym::Status());

        // Any address inside a loaded module must resolve at least to module+RVA.
        const void* here = reinterpret_cast<const void*>(&TestSymbols);
        CHECK(sym::Resolve(here, out, sizeof(out)));
        CHECK(::strstr(out, "selftest.exe") != nullptr);
        std::printf("  self  : %s\n", out);

        const void* sleepFn = plat::ImportedFunction(L"kernel32.dll", "Sleep");
        CHECK(sym::Resolve(sleepFn, out, sizeof(out)));
        CHECK(::_strnicmp(out, "kernel32", 8) == 0);
        std::printf("  export: %s\n", out);

        // This exe ships its own PDB, so we expect a real name here, not just module+RVA.
        if (ready)
        {
            sym::Resolve(here, out, sizeof(out));
            CHECK(::strchr(out, 0x21) != nullptr);   // 0x21 = '!', the module/symbol separator
        }
    }

    /*
    The OS layer behind Platform.h. Only the parts with a decision in them: the section filter and
    the cap. Everything the filter feeds -- the pattern scan above, the GObjects walk in Endpoint --
    silently finds nothing if this returns an empty or wrong set, which is the failure mode worth a
    check of its own.
    */
    void TestSections()
    {
        plat::Section all[plat::kMaxSections]{};
        const size_t n = plat::Sections(all, plat::kMaxSections, plat::SectionKind::Any);
        CHECK(n > 0);

        for (size_t i = 0; i < n; ++i)
        {
            CHECK(all[i].start != nullptr);
            CHECK(plat::InModule(all[i].start));
        }

        // This exe has code in it, and every executable section is one of the sections.
        plat::Section exec[plat::kMaxSections]{};
        const size_t e = plat::Sections(exec, plat::kMaxSections, plat::SectionKind::Executable);
        CHECK(e > 0 && e <= n);
        CHECK(plat::IsExecutable(exec[0].start));

        // A short buffer truncates rather than overruns.
        plat::Section one{};
        CHECK(plat::Sections(&one, 1, plat::SectionKind::Any) == 1);
        CHECK(plat::Sections(&one, 0, plat::SectionKind::Any) == 0);

        std::printf("section ok\n");
    }
}

int main()
{
    TestNames();
    TestPattern();
    TestBytecode();
    TestSymbols();
    TestSections();
    if (g_fails) { std::printf("%d CHECK(s) FAILED\n", g_fails); return 1; }
    std::printf("all ok\n");
    return 0;
}
