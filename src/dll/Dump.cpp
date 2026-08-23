#include "Dump.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <windows.h>

#include "Bytecode.h"
#include "Endpoint.h"
#include "Interceptor.h"
#include "NamePool.h"
#include "Platform.h"
#include "Symbols.h"
#include "Ue.h"

using namespace bpc;
using namespace bpc::ue;

extern HMODULE g_SelfModule;   // set in DllMain

namespace
{
    /* Output. One static buffer, appended to with sprintf and flushed with WriteFile. Nothing on
       this path uses std::string or ofstream, because the heap is a prime suspect at crash
       time. */

    constexpr size_t kBufSize = 1u << 20;
    char   g_buf[kBufSize];
    size_t g_len = 0;
    HANDLE g_file = INVALID_HANDLE_VALUE;

    void Flush()
    {
        if (g_file != INVALID_HANDLE_VALUE && g_len)
        {
            DWORD wrote = 0;
            ::WriteFile(g_file, g_buf, static_cast<DWORD>(g_len), &wrote, nullptr);
            ::FlushFileBuffers(g_file);
        }
        g_len = 0;
    }

    void Add(const char* fmt, ...)
    {
        if (g_len + 1024 > kBufSize) Flush();
        va_list ap;
        va_start(ap, fmt);
        const int n = ::vsnprintf(g_buf + g_len, kBufSize - g_len, fmt, ap);
        va_end(ap);
        if (n > 0) g_len += static_cast<size_t>(n);
    }

    // Directory of this DLL, with a trailing backslash. Every artifact is written beside it.
    void OurDir(wchar_t* path, size_t cap)
    {
        path[0] = 0;
        ::GetModuleFileNameW(g_SelfModule, path, static_cast<DWORD>(cap));
        wchar_t* slash = ::wcsrchr(path, L'\\');
        if (slash) slash[1] = 0;
    }

    /* Every report this process writes gets its own number. Without it the name resolves only to
       the second, and CREATE_ALWAYS then TRUNCATES the earlier one -- which is what cascading
       first-chance exceptions (and a self-test followed by an immediate crash) actually do, so
       the interesting report was being overwritten by the next one before anyone read it. */
    volatile LONG g_reportNo = 0;

    bool OpenReport(const char* reason)
    {
        wchar_t path[MAX_PATH]{};
        OurDir(path, MAX_PATH);

        SYSTEMTIME st{};
        ::GetLocalTime(&st);
        const LONG no = ::InterlockedIncrement(&g_reportNo);
        wchar_t name[160];
        ::swprintf_s(name, L"bpcrash_%04d%02d%02d_%02d%02d%02d_%lu_%02ld_t%lu.txt",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            ::GetCurrentProcessId(), no, ::GetCurrentThreadId());
        ::wcscat_s(path, name);

        g_file = ::CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (g_file == INVALID_HANDLE_VALUE) return false;

        g_len = 0;
        Add("=== BPCrashHandler report ===\n");
        Add("reason  : %s\n", reason);
        Add("pid     : %lu   thread: %lu\n", ::GetCurrentProcessId(), ::GetCurrentThreadId());
        Add("time    : %04d-%02d-%02d %02d:%02d:%02d\n\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        Add("%s\n\n", sym::Status());
        Add("--- endpoint self-test ---\n%s\n", endpoint::Report().c_str());
        return true;
    }

    void CloseReport()
    {
        Flush();
        if (g_file != INVALID_HANDLE_VALUE) { ::CloseHandle(g_file); g_file = INVALID_HANDLE_VALUE; }
    }

    /* Pass 1, the native context. Nothing here dereferences a UObject, so it survives even a
       fully corrupt engine. */

    const char* ExceptionName(DWORD code)
    {
        switch (code)
        {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE";
        default:                                 return "?";
        }
    }

    void DumpNative(EXCEPTION_POINTERS* ep)
    {
        Add("--- native context ---\n");
        Add("module  : 0x%p  size 0x%zX\n", plat::ModuleBase(), plat::ModuleSize());

        if (!ep) { Add("(no exception context)\n\n"); return; }

        const auto* er = ep->ExceptionRecord;
        const auto* cx = ep->ContextRecord;

        Add("code    : 0x%08lX %s\n", er->ExceptionCode, ExceptionName(er->ExceptionCode));
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
        {
            static const char* kOp[] = { "read", "write", "?", "?", "?", "?", "?", "?", "execute" };
            const ULONG_PTR kind = er->ExceptionInformation[0];
            Add("access  : %s at 0x%p\n",
                kind <= 8 ? kOp[kind] : "?", reinterpret_cast<void*>(er->ExceptionInformation[1]));
        }

        const auto rip = static_cast<uintptr_t>(cx->Rip);
        Add("rip     : 0x%p", reinterpret_cast<void*>(rip));
        if (plat::InModule(reinterpret_cast<void*>(rip)))
            Add("  (+0x%zX)", plat::Rva(reinterpret_cast<void*>(rip)));
        Add("\n");

        Add("regs    : rsp=0x%p rbp=0x%p rax=0x%p rcx=0x%p rdx=0x%p\n",
            (void*)cx->Rsp, (void*)cx->Rbp, (void*)cx->Rax, (void*)cx->Rcx, (void*)cx->Rdx);
        Add("          r8 =0x%p r9 =0x%p rbx=0x%p rsi=0x%p rdi=0x%p\n",
            (void*)cx->R8, (void*)cx->R9, (void*)cx->Rbx, (void*)cx->Rsi, (void*)cx->Rdi);

        if (!plat::BadRead(reinterpret_cast<void*>(rip), 16))
        {
            Add("bytes   :");
            const auto* p = reinterpret_cast<const uint8_t*>(rip);
            for (int i = 0; i < 16; ++i) Add(" %02X", p[i]);
            Add("\n");
        }

        /* Raw stack RVAs, kept short. The readable call stack is the symbolised one further
           down; this exists only so the addresses survive if that pass dies. */
        Add("stack   : (raw fallback -- read the call stack below instead)\n         ");
        const auto* sp = reinterpret_cast<const uintptr_t*>(cx->Rsp);
        int shown = 0;
        for (int i = 0; i < 8192 && shown < 48; ++i)
        {
            if (plat::BadRead(sp + i, 8)) break;
            const uintptr_t v = sp[i];
            if (!plat::InModule(reinterpret_cast<void*>(v))) continue;
            Add(" +%zX", plat::Rva(reinterpret_cast<void*>(v)));
            if (++shown % 8 == 0) Add("\n         ");
        }
        Add("\n\n");
    }

    /*
    Pass 2, the symbolised context. Everything here goes through dbghelp, which allocates, so none
    of it may run before the raw pass above is flushed to disk.

    In exchange the scan below is not limited to the game module: any injected DLL on the stack, be
    it a mod loader, an overlay, or tooling of your own, gets named out of its own PDB.
    */

    void DumpModules()
    {
        Add("--- loaded modules ---\n");
        sym::ForEachModule([](const char* name, const void* base, size_t size, void*)
        {
            Add("  0x%p  0x%08zX  %s\n", base, size, name);
        }, nullptr);
        Add("\n");
    }

    /*
    Does this address plausibly follow a call instruction? Used to filter the stack scan below.

    Taking every stack slot that points into a module picks up vtable pointers, string literals,
    and every stale frame the thread ever had, which is unreadable. A real return address has a
    call immediately before it, so we decode backwards. x86-64 calls are variable length, but only
    a few encodings matter in practice:

        E8 rel32            direct           5 bytes
        FF /2 disp32        indirect memory  6-7 bytes
        FF /2 (modrm)       indirect         2-3 bytes

    This is a heuristic rather than unwind data, so false positives still slip through, but it
    removes most of the noise and never needs RBP to be intact.
    */
    bool AfterCall(const uint8_t* ret)
    {
        if (plat::BadRead(ret - 8, 8)) return false;

        if (ret[-5] == 0xE8) return true;                                  // call rel32
        if (ret[-6] == 0xFF && (ret[-5] & 0x38) == 0x10) return true;      // call [rip+disp32]
        if (ret[-7] == 0xFF && (ret[-6] & 0x38) == 0x10) return true;      // call [reg+disp32]
        if (ret[-2] == 0xFF && (ret[-1] & 0xF8) == 0xD0) return true;      // call reg
        if (ret[-3] == 0xFF && (ret[-2] & 0x38) == 0x10) return true;      // call [reg] / [reg+disp8]
        return false;
    }

    void DumpSymbols(EXCEPTION_POINTERS* ep)
    {
        sym::Refresh();   // pick up anything injected after we loaded

        char line[768];
        if (ep && ep->ContextRecord)
        {
            const auto* cx = ep->ContextRecord;
            if (sym::Resolve(reinterpret_cast<void*>(cx->Rip), line, sizeof(line)))
                Add("--- faulting instruction ---\n%s\n\n", line);

            Add("--- native call stack (probable return addresses, any module) ---\n");
            const auto* sp = reinterpret_cast<const uintptr_t*>(cx->Rsp);
            int shown = 0;
            uintptr_t last = 0;
            for (int i = 0; i < 8192 && shown < 40; ++i)
            {
                if (plat::BadRead(sp + i, 8)) break;
                const auto v = sp[i];
                if (v == last) continue;                                    // repeated slot
                if (!plat::IsExecutable(reinterpret_cast<void*>(v))) continue;
                if (!AfterCall(reinterpret_cast<const uint8_t*>(v))) continue;
                if (!sym::Resolve(reinterpret_cast<void*>(v), line, sizeof(line))) continue;
                last = v;
                Add("  %2d  %s\n", shown, line);
                ++shown;
            }
            if (!shown) Add("  (nothing matched -- see the raw fallback above)\n");
        }
        Add("\n");
    }

    /* Value rendering, dispatched on FFieldClass::CastFlags, which is how we ask what kind of
       property something is with no generated SDK in the build. */

    void RenderValue(const uint8_t* base, FProperty* p, char* out, size_t cap, int depth);

    void RenderStruct(const uint8_t* v, FStructProperty* sp, char* out, size_t cap, int depth)
    {
        char sn[128] = "?";
        if (!plat::BadRead(sp->Struct, sizeof(UObject))) names::Of(sp->Struct, sn, sizeof(sn));

        const auto* f = reinterpret_cast<const float*>(v);
        if (!::strcmp(sn, "Vector"))      { ::sprintf_s(out, cap, "(%.3f, %.3f, %.3f)", f[0], f[1], f[2]); return; }
        if (!::strcmp(sn, "Rotator"))     { ::sprintf_s(out, cap, "(P=%.3f Y=%.3f R=%.3f)", f[0], f[1], f[2]); return; }
        if (!::strcmp(sn, "Vector2D"))    { ::sprintf_s(out, cap, "(%.3f, %.3f)", f[0], f[1]); return; }
        if (!::strcmp(sn, "LinearColor")) { ::sprintf_s(out, cap, "(R=%.3f G=%.3f B=%.3f A=%.3f)", f[0], f[1], f[2], f[3]); return; }

        // One level deep, first 6 members. Enough to see which field is wrong; go deeper only if
        // a nested struct ever hides the answer.
        if (depth > 0 || plat::BadRead(sp->Struct, sizeof(UStruct))) { ::sprintf_s(out, cap, "<F%s>", sn); return; }

        ::sprintf_s(out, cap, "F%s{", sn);
        int n = 0;
        for (FField* m : FieldRange(sp->Struct))
        {
            if (plat::BadRead(m, sizeof(FField))) break;
            if (!IsA(m, CAST_FProperty)) continue;
            if (n >= 6) { ::strncat_s(out, cap, " ...", _TRUNCATE); break; }
            char mn[128], mv[256], part[420];
            names::Of(m, mn, sizeof(mn));
            RenderValue(v, static_cast<FProperty*>(m), mv, sizeof(mv), depth + 1);
            ::sprintf_s(part, "%s%s=%s", n ? ", " : "", mn, mv);
            ::strncat_s(out, cap, part, _TRUNCATE);
            ++n;
        }
        ::strncat_s(out, cap, "}", _TRUNCATE);
    }

    void RenderValue(const uint8_t* base, FProperty* p, char* out, size_t cap, int depth)
    {
        out[0] = 0;
        if (plat::BadRead(p, sizeof(FProperty))) { ::strncpy_s(out, cap, "<prop?>", _TRUNCATE); return; }

        const uint8_t* v = base + p->Offset;
        const size_t   n = p->ElementSize > 0 ? static_cast<size_t>(p->ElementSize) : 1;
        if (plat::BadRead(v, n)) { ::strncpy_s(out, cap, "<unreadable>", _TRUNCATE); return; }

        const uint64_t cf = plat::BadRead(p->ClassPrivate, sizeof(FFieldClass)) ? 0 : p->ClassPrivate->CastFlags;

        if (cf & CAST_FBoolProperty)
        {
            auto* bp = static_cast<FBoolProperty*>(p);
            ::sprintf_s(out, cap, "%s", (*v & bp->ByteMask) ? "true" : "false");
        }
        else if (cf & CAST_FIntProperty)    ::sprintf_s(out, cap, "%d",   *reinterpret_cast<const int32_t*>(v));
        else if (cf & CAST_FInt64Property)  ::sprintf_s(out, cap, "%lld", *reinterpret_cast<const int64_t*>(v));
        else if (cf & CAST_FInt16Property)  ::sprintf_s(out, cap, "%d",   *reinterpret_cast<const int16_t*>(v));
        else if (cf & CAST_FInt8Property)   ::sprintf_s(out, cap, "%d",   *reinterpret_cast<const int8_t*>(v));
        else if (cf & CAST_FUInt64Property) ::sprintf_s(out, cap, "%llu", *reinterpret_cast<const uint64_t*>(v));
        else if (cf & CAST_FUInt32Property) ::sprintf_s(out, cap, "%u",   *reinterpret_cast<const uint32_t*>(v));
        else if (cf & CAST_FUInt16Property) ::sprintf_s(out, cap, "%u",   *reinterpret_cast<const uint16_t*>(v));
        else if (cf & CAST_FFloatProperty)  ::sprintf_s(out, cap, "%.6g", *reinterpret_cast<const float*>(v));
        else if (cf & CAST_FDoubleProperty) ::sprintf_s(out, cap, "%.6g", *reinterpret_cast<const double*>(v));
        // Enums print numerically. UEnum's name table is a TMap walk away; add it only if a dump
        // ever leaves you unable to tell which case fired.
        else if (cf & CAST_FEnumProperty)
        {
            auto* ep = static_cast<FEnumProperty*>(p);
            int sz = plat::BadRead(ep->Underlying, sizeof(FProperty)) ? 1 : ep->Underlying->ElementSize;
            if (sz < 1 || sz > 8) sz = 1;
            uint64_t raw = 0;
            ::memcpy(&raw, v, sz);
            ::sprintf_s(out, cap, "%llu (enum)", raw);
        }
        else if (cf & CAST_FByteProperty)   ::sprintf_s(out, cap, "%u", *v);
        else if (cf & CAST_FNameProperty)   names::Decode(*reinterpret_cast<const FName*>(v), out, cap);
        else if (cf & CAST_FStrProperty)
        {
            const auto* s = reinterpret_cast<const FString*>(v);
            if (!s->Data || s->Num <= 1 || s->Num > 4096 || plat::BadRead(s->Data, 2))
            {
                ::strncpy_s(out, cap, "\"\"", _TRUNCATE);
            }
            else
            {
                const int lim = static_cast<int>(cap) - 4;
                const int len = (s->Num - 1 < lim) ? s->Num - 1 : lim;
                int w = 0;
                out[w++] = '"';
                for (int i = 0; i < len; ++i)
                    out[w++] = (s->Data[i] > 0 && s->Data[i] < 0x80) ? static_cast<char>(s->Data[i]) : '?';
                out[w++] = '"';
                out[w] = 0;
            }
        }
        else if (cf & CAST_FTextProperty)   ::strncpy_s(out, cap, "<FText>", _TRUNCATE);
        else if (cf & CAST_FObjectPropertyBase)
        {
            auto* o = *reinterpret_cast<UObject* const*>(v);
            if (!o) ::strncpy_s(out, cap, "null", _TRUNCATE);
            else if (plat::BadRead(o, sizeof(UObject))) ::sprintf_s(out, cap, "0x%p <bad>", o);
            else
            {
                char cn[128] = "?", on[256];
                if (!plat::BadRead(o->Class, sizeof(UObject))) names::Of(o->Class, cn, sizeof(cn));
                names::Of(o, on, sizeof(on));
                ::sprintf_s(out, cap, "%s'%s' @0x%p", cn, on, o);
            }
        }
        else if (cf & CAST_FStructProperty) RenderStruct(v, static_cast<FStructProperty*>(p), out, cap, depth);
        else if (cf & CAST_FArrayProperty)
        {
            auto* ap = static_cast<FArrayProperty*>(p);
            const auto* arr = reinterpret_cast<const FScriptArray*>(v);
            if (arr->Num < 0 || arr->Num > arr->Max || arr->Max > (1 << 24))
                ::strncpy_s(out, cap, "<corrupt array>", _TRUNCATE);
            else if (!arr->Num)
                ::strncpy_s(out, cap, "[0]", _TRUNCATE);
            else if (plat::BadRead(arr->Data, 1) || plat::BadRead(ap->Inner, sizeof(FProperty)))
                ::sprintf_s(out, cap, "[%d] <unreadable>", arr->Num);
            else
            {
                ::sprintf_s(out, cap, "[%d] {", arr->Num);
                const int show = arr->Num < 8 ? arr->Num : 8;
                for (int i = 0; i < show; ++i)
                {
                    char ev[256], part[300];
                    // Inner->Offset is 0 within an element, so the element base IS the value base.
                    RenderValue(static_cast<const uint8_t*>(arr->Data) + i * ap->Inner->ElementSize,
                                ap->Inner, ev, sizeof(ev), depth + 1);
                    ::sprintf_s(part, "%s%s", i ? ", " : "", ev);
                    ::strncat_s(out, cap, part, _TRUNCATE);
                }
                ::strncat_s(out, cap, arr->Num > show ? ", ...}" : "}", _TRUNCATE);
            }
        }
        else if (cf & (CAST_FDelegateProperty | CAST_FMulticastDelegateProperty))
            ::strncpy_s(out, cap, "<delegate>", _TRUNCATE);
        else if (cf & (CAST_FMapProperty | CAST_FSetProperty))
            ::strncpy_s(out, cap, "<container>", _TRUNCATE);
        else
        {
            char tn[128] = "?";
            if (!plat::BadRead(p->ClassPrivate, sizeof(FFieldClass)))
                names::Decode(p->ClassPrivate->Name, tn, sizeof(tn));
            ::sprintf_s(out, cap, "<%s>", tn);
        }
    }

    // Blueprint frames.

    const char* ParmTag(uint64_t flags)
    {
        if (flags & CPF_ReturnParm) return "ret";
        if (flags & CPF_OutParm)    return (flags & CPF_ReferenceParm) ? "in/out" : "out";
        return "in";
    }

    /*
    Walk a UFunction's property chain over `base` and print each value.

    `parmsOnly` is for a ProcessEvent frame, whose buffer covers the parameter block and nothing
    else; reading a true local's offset off it would run past the end and print noise. A VM
    frame's Locals buffer holds both, and both get printed, tagged.
    */
    int DumpProperties(UFunction* node, const uint8_t* base, bool parmsOnly)
    {
        int printed = 0;
        for (FField* f : FieldRange(node))
        {
            if (plat::BadRead(f, sizeof(FField)) || !IsA(f, CAST_FProperty)) break;

            auto* p = static_cast<FProperty*>(f);
            const bool isParm = (p->PropertyFlags & CPF_Parm) != 0;
            if (parmsOnly && !isParm) continue;

            char n[128], val[512];
            names::Of(f, n, sizeof(n));
            RenderValue(base, p, val, sizeof(val), 0);
            Add("       %-6s %-28s = %s\n", isParm ? ParmTag(p->PropertyFlags) : "local", n, val);
            if (++printed > 64) { Add("       ...\n"); break; }
        }
        return printed;
    }

    void DumpFrameBody(int i, const interceptor::Frame& fr)
    {
        char path[512] = "<none>";
        if (!plat::BadRead(fr.node, sizeof(UFunction))) names::PathOf(fr.node, path, sizeof(path));

        char self[512] = "<none>";
        if (!plat::BadRead(fr.obj, sizeof(UObject))) names::PathOf(fr.obj, self, sizeof(self));

        Add("#%-2d %s\n", i, path);
        Add("     self   : %s\n", self);

        if (!fr.frame)
        {
            /* Native entry via ProcessEvent. There is no VM frame, and therefore no locals and no
               bytecode offset, but the arguments the call was made with are right here. */
            Add("     kind   : native call via ProcessEvent (no VM frame)\n");
            if (plat::BadRead(fr.parms, 1))
            {
                Add("     args   : <none>\n\n");
                return;
            }
            Add("     args   :\n");
            if (!DumpProperties(fr.node, static_cast<const uint8_t*>(fr.parms), true))
                Add("       (function declares no parameters)\n");
            Add("\n");
            return;
        }
        if (plat::BadRead(fr.frame, sizeof(FFrame)))
        {
            Add("     (frame unreadable)\n\n");
            return;
        }

        // The bytecode offset is the distance from the function's script blob to FFrame::Code.
        if (!plat::BadRead(fr.node, sizeof(UStruct)) && fr.node->ScriptData && fr.frame->Code)
        {
            const auto off = static_cast<ptrdiff_t>(fr.frame->Code - fr.node->ScriptData);
            char insn[320];
            bytecode::Describe(fr.frame->Code, insn, sizeof(insn));
            if (off >= 0 && off <= fr.node->ScriptNum)
                Add("     offset : 0x%04zX / 0x%04X   %s\n", off, fr.node->ScriptNum, insn);
            else
                Add("     offset : <out of range>       %s\n", insn);
        }

        if (plat::BadRead(fr.frame->Locals, 1))
        {
            Add("     locals : <no frame buffer>\n\n");
            return;
        }

        Add("     locals :\n");
        if (!DumpProperties(fr.node, fr.frame->Locals, false))
            Add("       (function declares no parameters or locals)\n");
        Add("\n");
    }

    // Each frame gets its own SEH box, so one bad frame costs that frame and not the report.
    void DumpFrameSafe(int i, const interceptor::Frame& fr)
    {
        __try { DumpFrameBody(i, fr); }
        __except (EXCEPTION_EXECUTE_HANDLER) { Add("#%-2d <faulted while dumping this frame>\n\n", i); }
    }

    void DumpBlueprint()
    {
        int count = 0;
        const interceptor::Frame* frames = interceptor::Stack(count);

        Add("--- blueprint call stack (%d frame%s, innermost first) ---\n", count, count == 1 ? "" : "s");
        if (!count)
        {
            Add("(none -- this thread was not inside the Blueprint VM)\n\n");
            return;
        }
        /* The recorder keeps the outermost frames and drops the rest, so a runaway recursion --
           the usual cause of a stack overflow -- is missing the frames it actually died in. The
           repeating cycle is still visible in what survived. */
        if (count >= interceptor::kMaxDepth)
            Add("(depth cap reached -- the innermost frames past #%d were dropped)\n", count - 1);
        for (int i = count - 1; i >= 0; --i)
            DumpFrameSafe(count - 1 - i, frames[i]);
    }

    // The handler.

    volatile LONG g_inHandler = 0;
    volatile LONG g_seq = 0;        // every fatal-class exception seen, reported or skipped
    PVOID         g_veh = nullptr;

    bool IsFatal(DWORD code)
    {
        switch (code)
        {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return true;
        default:
            // C++ EH (0xE06D7363), debugger events, SetThreadName and friends are not crashes.
            return false;
        }
    }

    void WriteReport(const char* reason, EXCEPTION_POINTERS* ep)
    {
        /* Every stage is boxed and CloseReport always runs. A fault escaping from here would
           leak the re-entrancy flag and silently disable the tool for the rest of the session. */
        __try
        {
            if (!OpenReport(reason)) return;
            DumpNative(ep);
            Flush();             // pass 1 is on disk before anything risky runs

            __try { DumpModules(); DumpSymbols(ep); }
            __except (EXCEPTION_EXECUTE_HANDLER) { Add("<symbol pass faulted>\n"); }
            Flush();

            __try { DumpBlueprint(); }
            __except (EXCEPTION_EXECUTE_HANDLER) { Add("<blueprint pass faulted>\n"); }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
        CloseReport();
    }

    /*
    A vectored handler sees first-chance exceptions, running before any __except downstream, so an
    exception reported here may still be caught and recovered from and the process may carry on.
    That is the price of never missing the fatal one, and it is why each report is titled
    first-chance rather than "the crash". When several arrive, the last one is usually the
    interesting one.

    It also means our view and the engine's own crash reporter can disagree. UE only reports the
    exception its SEH caught, so a recovered fault upstream is invisible to it, and a fault raised
    inside its own crash path can replace the original in its record.
    */
    LONG CALLBACK Handler(EXCEPTION_POINTERS* ep)
    {
        if (!ep || !ep->ExceptionRecord || !IsFatal(ep->ExceptionRecord->ExceptionCode))
            return EXCEPTION_CONTINUE_SEARCH;

        const auto* er = ep->ExceptionRecord;
        const LONG seq = ::InterlockedIncrement(&g_seq);

        char note[320];
        ::sprintf_s(note, "exception #%ld  0x%08lX %s  at 0x%p  thread %lu",
                    seq, er->ExceptionCode, ExceptionName(er->ExceptionCode),
                    er->ExceptionAddress, ::GetCurrentThreadId());

        // A fault raised by our own dumping must not recurse back into it.
        if (::InterlockedCompareExchange(&g_inHandler, 1, 0) != 0)
        {
            ::strcat_s(note, "  -- SKIPPED (already inside the handler)");
            dump::Breadcrumb(note);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        dump::Breadcrumb(note);

        char reason[64];
        ::sprintf_s(reason, "first-chance exception #%ld", seq);
        WriteReport(reason, ep);

        ::InterlockedExchange(&g_inHandler, 0);
        return EXCEPTION_CONTINUE_SEARCH;   // observe, never swallow
    }
}

void bpc::dump::Breadcrumb(const char* phase)
{
    static bool s_started = false;

    wchar_t path[MAX_PATH]{};
    OurDir(path, MAX_PATH);
    ::wcscat_s(path, L"bpcrash_status.txt");

    HANDLE h = ::CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                             s_started ? OPEN_ALWAYS : CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    s_started = true;

    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    char line[512];
    const int n = ::sprintf_s(line, "%02d:%02d:%02d  %s\r\n", st.wHour, st.wMinute, st.wSecond, phase);

    DWORD wrote = 0;
    ::SetFilePointer(h, 0, nullptr, FILE_END);
    ::WriteFile(h, line, static_cast<DWORD>(n), &wrote, nullptr);
    ::FlushFileBuffers(h);
    ::CloseHandle(h);
}

void bpc::dump::Arm()
{
    if (!g_veh) g_veh = ::AddVectoredExceptionHandler(1, &Handler);
}

void bpc::dump::WriteNow(const char* reason)
{
    if (::InterlockedCompareExchange(&g_inHandler, 1, 0) != 0) return;
    WriteReport(reason, nullptr);
    ::InterlockedExchange(&g_inHandler, 0);
}
