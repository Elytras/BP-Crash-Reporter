#include "Interceptor.h"

#include <MinHook.h>

#include "Endpoint.h"

using namespace bpc;
using namespace bpc::ue;

namespace
{
    constexpr int kMaxDepth = interceptor::kMaxDepth;

    /*
    Per-thread state, kept behind the plain Win32 TLS API (TlsAlloc/TlsGetValue/TlsSetValue)
    rather than the C++ `thread_local` keyword.

    `thread_local` compiles to code that computes an address through the module's `_tls_index`
    and a per-thread TLS block, and on this toolchain that codegen carries a base-relocation bug:
    when bpcrash_live.dll doesn't load at its preferred address -- routine in a real game's
    crowded address space, never seen in the mostly-empty tests/hostload.exe harness -- the
    loader's rebase pass corrupts the upper 16 bits of the small constant offset baked into that
    address computation (an IMAGE_REL_BASED_HIGH-shaped relocation applied to what is actually
    just a struct-member offset, not a pointer). That turns a harmless read into a wild
    dereference, differently on every run depending on the load-address delta. Reproduced twice
    against real Deep Rock Galactic under Proton, at two different call sites, both times with the
    low 16 bits of the corrupted offset intact and only the upper 16 bits garbled -- the signature
    of exactly that relocation type. TlsGetValue/TlsSetValue are ordinary function calls with no
    address-computation codegen for the loader to get wrong.
    */
    struct ThreadState
    {
        interceptor::Frame stack[kMaxDepth];
        int  depth = 0;
        bool guaranteed = false;
    };

    DWORD g_tlsIndex = TLS_OUT_OF_INDEXES;

    // Hook path only (normal execution, never the crash handler): allocates on first touch.
    ThreadState& State()
    {
        void* p = ::TlsGetValue(g_tlsIndex);
        if (!p)
        {
            p = new ThreadState();
            ::TlsSetValue(g_tlsIndex, p);
        }
        return *static_cast<ThreadState*>(p);
    }

    struct Scope
    {
        ThreadState& ts;
        bool pushed;
        Scope(ThreadState& s, UFunction* n, UObject* o, FFrame* f, void* parms = nullptr) : ts(s)
        {
            pushed = ts.depth < kMaxDepth;
            if (pushed) ts.stack[ts.depth++] = { n, o, f, parms };
        }
        ~Scope() { if (pushed) --ts.depth; }
    };

    using PeFn = void(__fastcall*)(UObject*, UFunction*, void*);
    using PiFn = void(__fastcall*)(UObject*, FFrame&, void*);

    PeFn o_ProcessEvent = nullptr;
    PiFn o_ProcessInternal = nullptr;
    PiFn o_ProcessLocal = nullptr;
    bool g_installed = false;

    /*
    Reserves a cushion below the guard page for the calling thread, once, on the first VM call we
    see from it. Dump.cpp runs on the faulting thread, so on a stack overflow it inherits whatever
    is left: without the cushion that is about a page, enough for the native context and nothing
    after it -- the module list, the symbols and the Blueprint frames all die in a second overflow
    partway through. 64 KB is what tests/hostload.exe --overflow needed for a complete report.

    Only threads that run Blueprint get this, which is every thread this tool has anything to say
    about. One that overflows having never called a UFunction still writes the truncated report.
    */
    void EnsureHeadroom(ThreadState& ts)
    {
        if (ts.guaranteed) return;
        ts.guaranteed = true;
        ULONG bytes = 64 * 1024;
        ::SetThreadStackGuarantee(&bytes);
    }

    void __fastcall HookProcessEvent(UObject* self, UFunction* fn, void* parms)
    {
        ThreadState& ts = State();
        EnsureHeadroom(ts);
        // Scripted targets are recorded by ProcessInternal instead; see the header.
        const bool scripted = fn && reinterpret_cast<void*>(fn->ExecFunction) == endpoint::Get().processInternal;
        if (scripted)
        {
            o_ProcessEvent(self, fn, parms);
            return;
        }
        Scope s(ts, fn, self, nullptr, parms);
        o_ProcessEvent(self, fn, parms);
    }

    /*
    Runs for every scripted function body, however it was entered. ProcessInternal delegates here,
    so the two hooks would double-count that one path. They share the same FFrame object, so
    comparing `&stack` against the top frame is an exact test for the duplicate.
    */
    void __fastcall HookProcessLocal(UObject* self, FFrame& stack, void* result)
    {
        ThreadState& ts = State();
        EnsureHeadroom(ts);
        if (ts.depth > 0 && ts.stack[ts.depth - 1].frame == &stack)
        {
            o_ProcessLocal(self, stack, result);   // ProcessInternal already recorded this frame
            return;
        }
        Scope s(ts, stack.Node, self, &stack);
        o_ProcessLocal(self, stack, result);
    }

    void __fastcall HookProcessInternal(UObject* self, FFrame& stack, void* result)
    {
        ThreadState& ts = State();
        EnsureHeadroom(ts);
        Scope s(ts, stack.Node, self, &stack);
        o_ProcessInternal(self, stack, result);
    }

    bool Hook(void* target, void* detour, void** orig)
    {
        return target
            && MH_CreateHook(target, detour, orig) == MH_OK
            && MH_EnableHook(target) == MH_OK;
    }
}

const interceptor::Frame* interceptor::Stack(int& count)
{
    // Crash path: never allocate. No TLS entry for this thread just means it never ran
    // Blueprint, which is the same thing an untouched thread_local would have reported.
    void* p = (g_tlsIndex != TLS_OUT_OF_INDEXES) ? ::TlsGetValue(g_tlsIndex) : nullptr;
    if (!p) { count = 0; return nullptr; }
    auto* ts = static_cast<ThreadState*>(p);
    count = ts->depth;
    return ts->stack;
}

bool interceptor::Install()
{
    if (g_installed) return true;
    if (g_tlsIndex == TLS_OUT_OF_INDEXES)
    {
        g_tlsIndex = ::TlsAlloc();
        if (g_tlsIndex == TLS_OUT_OF_INDEXES) return false;
    }
    if (MH_Initialize() != MH_OK) return false;

    const auto& r = endpoint::Get();
    // A calling-convention-tagged function pointer isn't implicitly convertible to void* here
    // the way MSVC allows; reinterpret_cast it explicitly, same as `orig` below already does.
    const bool pi = Hook(r.processInternal, reinterpret_cast<void*>(&HookProcessInternal),
                          reinterpret_cast<void**>(&o_ProcessInternal));
    Hook(r.processEvent, reinterpret_cast<void*>(&HookProcessEvent),
         reinterpret_cast<void**>(&o_ProcessEvent));   // optional
    Hook(r.processLocal, reinterpret_cast<void*>(&HookProcessLocal),
         reinterpret_cast<void**>(&o_ProcessLocal));   // BP -> BP

    g_installed = pi;
    return pi;   // without ProcessInternal there is no Blueprint stack at all
}

void interceptor::Uninstall()
{
    if (!g_installed) return;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_installed = false;
}
