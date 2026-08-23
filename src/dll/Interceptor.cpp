#include "Interceptor.h"

#include <MinHook.h>

#include "Endpoint.h"

using namespace bpc;
using namespace bpc::ue;

namespace
{
    constexpr int kMaxDepth = interceptor::kMaxDepth;

    thread_local interceptor::Frame t_stack[kMaxDepth];
    thread_local int                t_depth = 0;

    struct Scope
    {
        bool pushed;
        Scope(UFunction* n, UObject* o, FFrame* f, void* parms = nullptr)
        {
            pushed = t_depth < kMaxDepth;
            if (pushed) t_stack[t_depth++] = { n, o, f, parms };
        }
        ~Scope() { if (pushed) --t_depth; }
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
    void EnsureHeadroom()
    {
        static thread_local bool s_guaranteed = [] {
            ULONG bytes = 64 * 1024;
            ::SetThreadStackGuarantee(&bytes);
            return true;
        }();
        (void)s_guaranteed;
    }

    void __fastcall HookProcessEvent(UObject* self, UFunction* fn, void* parms)
    {
        EnsureHeadroom();
        // Scripted targets are recorded by ProcessInternal instead; see the header.
        const bool scripted = fn && reinterpret_cast<void*>(fn->ExecFunction) == endpoint::Get().processInternal;
        if (scripted)
        {
            o_ProcessEvent(self, fn, parms);
            return;
        }
        Scope s(fn, self, nullptr, parms);
        o_ProcessEvent(self, fn, parms);
    }

    /*
    Runs for every scripted function body, however it was entered. ProcessInternal delegates here,
    so the two hooks would double-count that one path. They share the same FFrame object, so
    comparing `&stack` against the top frame is an exact test for the duplicate.
    */
    void __fastcall HookProcessLocal(UObject* self, FFrame& stack, void* result)
    {
        EnsureHeadroom();
        if (t_depth > 0 && t_stack[t_depth - 1].frame == &stack)
        {
            o_ProcessLocal(self, stack, result);   // ProcessInternal already recorded this frame
            return;
        }
        Scope s(stack.Node, self, &stack);
        o_ProcessLocal(self, stack, result);
    }

    void __fastcall HookProcessInternal(UObject* self, FFrame& stack, void* result)
    {
        EnsureHeadroom();
        Scope s(stack.Node, self, &stack);
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
    count = t_depth;
    return t_stack;
}

bool interceptor::Install()
{
    if (g_installed) return true;
    if (MH_Initialize() != MH_OK) return false;

    const auto& r = endpoint::Get();
    const bool pi = Hook(r.processInternal, &HookProcessInternal, reinterpret_cast<void**>(&o_ProcessInternal));
    Hook(r.processEvent, &HookProcessEvent, reinterpret_cast<void**>(&o_ProcessEvent));   // optional
    Hook(r.processLocal, &HookProcessLocal, reinterpret_cast<void**>(&o_ProcessLocal));   // BP -> BP

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
