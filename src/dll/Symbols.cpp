#include "Symbols.h"

#include <cstdio>
#include <cstring>
#include <windows.h>

#include <dbghelp.h>      // structs only; nothing is linked against dbghelp.lib
#include <psapi.h>

#include "Platform.h"

namespace
{
    using PFN_SymSetOptions   = DWORD   (WINAPI*)(DWORD);
    using PFN_SymInitializeW  = BOOL    (WINAPI*)(HANDLE, PCWSTR, BOOL);
    using PFN_SymFromAddr     = BOOL    (WINAPI*)(HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO);
    using PFN_SymRefresh      = BOOL    (WINAPI*)(HANDLE);
    using PFN_SymLoadModuleExW= DWORD64 (WINAPI*)(HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD);
    using PFN_SymUnloadModule = BOOL    (WINAPI*)(HANDLE, DWORD64);
    using PFN_SymGetModInfoW  = BOOL    (WINAPI*)(HANDLE, DWORD64, PIMAGEHLP_MODULEW64);
    using PFN_SymFromName     = BOOL    (WINAPI*)(HANDLE, PCSTR, PSYMBOL_INFO);

    PFN_SymSetOptions    p_SymSetOptions = nullptr;
    PFN_SymInitializeW   p_SymInitializeW = nullptr;
    PFN_SymFromAddr      p_SymFromAddr = nullptr;
    PFN_SymRefresh       p_SymRefreshModuleList = nullptr;
    PFN_SymLoadModuleExW p_SymLoadModuleExW = nullptr;
    PFN_SymUnloadModule  p_SymUnloadModule64 = nullptr;
    PFN_SymGetModInfoW   p_SymGetModuleInfoW64 = nullptr;
    PFN_SymFromName      p_SymFromName = nullptr;

    bool g_ready = false;
    char g_status[256] = "symbols: not initialised";

    HANDLE Self() { return ::GetCurrentProcess(); }

    /*
    Points dbghelp at <exe>.pdb by hand, which is what makes a generated PDB usable at all.

    A shipping UE build has its CodeView debug directory stripped, so the binary carries no PDB
    name and dbghelp has nothing to look for; it will not guess one from the exe's filename.
    SYMOPT_LOAD_ANYTHING does not help here, since it relaxes the signature check rather than the
    absence of a name. Passing the .pdb itself as SymLoadModuleExW's ImageName skips the lookup
    entirely and binds those symbols to the module's real base.
    */
    bool LoadMainModulePdb()
    {
        if (!p_SymLoadModuleExW) return false;

        wchar_t pdb[MAX_PATH]{};
        ::GetModuleFileNameW(nullptr, pdb, MAX_PATH);
        wchar_t* dot = ::wcsrchr(pdb, L'.');
        if (!dot) return false;
        ::wcscpy_s(dot, MAX_PATH - (dot - pdb), L".pdb");
        if (::GetFileAttributesW(pdb) == INVALID_FILE_ATTRIBUTES) return false;

        const auto base = reinterpret_cast<DWORD64>(bpc::plat::ModuleBase());
        if (p_SymUnloadModule64) p_SymUnloadModule64(Self(), base);   // drop the symbol-less entry
        return p_SymLoadModuleExW(Self(), nullptr, pdb, nullptr, base,
                                  static_cast<DWORD>(bpc::plat::ModuleSize()), nullptr, 0) != 0;
    }

    // What dbghelp ended up with for a module, so the status line reports it rather than guesses.
    const char* SymTypeName(DWORD64 base)
    {
        if (!p_SymGetModuleInfoW64) return "unknown";
        IMAGEHLP_MODULEW64 mi{};
        mi.SizeOfStruct = sizeof(mi);
        if (!p_SymGetModuleInfoW64(Self(), base, &mi)) return "not loaded";
        switch (mi.SymType)
        {
        case SymPdb:      return "PDB";
        case SymExport:   return "exports only";
        case SymDeferred: return "deferred";
        case SymCoff:     return "COFF";
        case SymCv:       return "CodeView";
        case SymNone:     return "none";
        default:          return "other";
        }
    }

    /*
    Base name of the main module, no extension -- the form dbghelp wants on the left of a
    "module!symbol" query. Computed once; the main module never moves.
    */
    const char* MainModuleName()
    {
        static char name[MAX_PATH]{};
        if (!name[0])
        {
            char path[MAX_PATH]{};
            ::GetModuleFileNameA(reinterpret_cast<HMODULE>(const_cast<uint8_t*>(bpc::plat::ModuleBase())),
                                 path, MAX_PATH);
            const char* slash = ::strrchr(path, '\\');
            ::strcpy_s(name, slash ? slash + 1 : path);
            if (char* dot = ::strrchr(name, '.')) *dot = 0;
            if (!name[0]) ::strcpy_s(name, "*");
        }
        return name;
    }

    bool LookUp(const char* query, PSYMBOL_INFO si)
    {
        __try { return p_SymFromName(Self(), query, si) && si->Address; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
}

bool bpc::sym::Init()
{
    if (g_ready) return true;

    /* Kill switch. Symbols are the one part of the tool that pulls in a large, slow, third-party
       component, so BPCRASH_SYMBOLS=0 rules it out when diagnosing a startup problem. */
    wchar_t off[8]{};
    if (::GetEnvironmentVariableW(L"BPCRASH_SYMBOLS", off, 8) && off[0] == L'0')
    {
        ::strcpy_s(g_status, "symbols: disabled by BPCRASH_SYMBOLS=0 -- addresses stay numeric");
        return false;
    }

    /* System32 only. Game folders do ship their own dbghelp.dll, and binding to one would mean
       running someone else's code inside our crash path. */
    HMODULE dbg = ::LoadLibraryExW(L"dbghelp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!dbg)
    {
        ::strcpy_s(g_status, "symbols: dbghelp.dll not available -- addresses stay numeric");
        return false;
    }

    p_SymSetOptions        = reinterpret_cast<PFN_SymSetOptions>(::GetProcAddress(dbg, "SymSetOptions"));
    p_SymInitializeW       = reinterpret_cast<PFN_SymInitializeW>(::GetProcAddress(dbg, "SymInitializeW"));
    p_SymFromAddr          = reinterpret_cast<PFN_SymFromAddr>(::GetProcAddress(dbg, "SymFromAddr"));
    p_SymRefreshModuleList = reinterpret_cast<PFN_SymRefresh>(::GetProcAddress(dbg, "SymRefreshModuleList"));
    p_SymLoadModuleExW     = reinterpret_cast<PFN_SymLoadModuleExW>(::GetProcAddress(dbg, "SymLoadModuleExW"));
    p_SymUnloadModule64    = reinterpret_cast<PFN_SymUnloadModule>(::GetProcAddress(dbg, "SymUnloadModule64"));
    p_SymGetModuleInfoW64  = reinterpret_cast<PFN_SymGetModInfoW>(::GetProcAddress(dbg, "SymGetModuleInfoW64"));
    p_SymFromName          = reinterpret_cast<PFN_SymFromName>(::GetProcAddress(dbg, "SymFromName"));

    if (!p_SymSetOptions || !p_SymInitializeW || !p_SymFromAddr)
    {
        ::strcpy_s(g_status, "symbols: dbghelp is missing entry points -- addresses stay numeric");
        return false;
    }

    /* LOAD_ANYTHING is the flag that matters here: the PDBs beside these game exes are generated
       rather than shipped, so their signature does not match the binary and dbghelp would
       otherwise reject them. */
    p_SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_ANYTHING |
                    SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);

    /* We set the search path explicitly rather than take dbghelp's default, which inherits
       _NT_SYMBOL_PATH. On a machine used for reverse engineering that usually names a symbol
       server, and a network fetch is unacceptable both at load (a startup stall) and at crash
       time (a hang in the handler). Two local directories only: the exe's, and this DLL's. */
    wchar_t search[MAX_PATH * 2 + 2]{};
    {
        wchar_t buf[MAX_PATH];
        ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
        if (wchar_t* s = ::wcsrchr(buf, L'\\')) *s = 0;
        ::wcscpy_s(search, buf);

        HMODULE self = nullptr;
        ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             reinterpret_cast<LPCWSTR>(&Init), &self);
        ::GetModuleFileNameW(self, buf, MAX_PATH);
        if (wchar_t* s = ::wcsrchr(buf, L'\\')) *s = 0;
        ::wcscat_s(search, L";");
        ::wcscat_s(search, buf);
    }

    /* invade = FALSE. Invading enumerates and registers every module in the process, 250 or more
       in a shipping UE game, and that work belongs at crash time in the single guarded Refresh()
       rather than in the game's startup path. */
    if (!p_SymInitializeW(Self(), search, FALSE))
    {
        ::sprintf_s(g_status, "symbols: SymInitialize failed (%lu) -- addresses stay numeric", ::GetLastError());
        return false;
    }
    g_ready = true;
    Refresh();   // register the modules loaded so far, locally, with no server behind it

    const bool byHand = LoadMainModulePdb();

    /* Force the game module's symbols resident now. With deferred loading the first lookup would
       happen inside the crash handler, parsing tens of MB through a heap that is a prime suspect
       at that moment. */
    char probe[512];
    Resolve(plat::ModuleBase() + 0x1000, probe, sizeof(probe));

    ::sprintf_s(g_status, "symbols: ready -- main module: %s%s",
                SymTypeName(reinterpret_cast<DWORD64>(plat::ModuleBase())),
                byHand ? " (loaded by explicit path)" : "");
    return true;
}

bool bpc::sym::Ready() { return g_ready; }

const char* bpc::sym::Status() { return g_status; }

void bpc::sym::Refresh()
{
    if (g_ready && p_SymRefreshModuleList) p_SymRefreshModuleList(Self());
}

bool bpc::sym::Resolve(const void* addr, char* out, size_t cap)
{
    out[0] = 0;
    if (!addr) return false;

    HMODULE mod = nullptr;
    if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(addr), &mod) || !mod)
        return false;   // not in any loaded module: heap, stack, or JIT

    wchar_t wpath[MAX_PATH]{};
    ::GetModuleFileNameW(mod, wpath, MAX_PATH);
    const wchar_t* wname = ::wcsrchr(wpath, L'\\');
    wname = wname ? wname + 1 : wpath;

    char name[128];
    ::WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, sizeof(name), nullptr, nullptr);

    const auto rva = reinterpret_cast<uintptr_t>(addr) - reinterpret_cast<uintptr_t>(mod);

    if (g_ready)
    {
        // SYMBOL_INFO is variable-length: the name lives past the struct.
        alignas(8) uint8_t storage[sizeof(SYMBOL_INFO) + 1024]{};
        auto* si = reinterpret_cast<PSYMBOL_INFO>(storage);
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen = 1023;

        DWORD64 disp = 0;
        __try
        {
            if (p_SymFromAddr(Self(), reinterpret_cast<DWORD64>(addr), &disp, si) && si->Name[0])
            {
                /* Sanity-check the displacement. These PDBs are generated and have gaps, so
                   dbghelp attributes an address to whatever public symbol precedes it, and
                   +0x1B13 into "CheatGodMode_Implementation" is a guess rather than a fact. Past
                   a plausible function size we lead with module+RVA and demote the symbol to a
                   hint, and drop it entirely if the displacement is nonsense. */
                if (disp == 0)              ::sprintf_s(out, cap, "%s!%s", name, si->Name);
                else if (disp <= 0x1000)    ::sprintf_s(out, cap, "%s!%s+0x%llX", name, si->Name, disp);
                else if (disp <= 0x100000)  ::sprintf_s(out, cap, "%s+0x%zX  (nearest: %s+0x%llX)",
                                                        name, rva, si->Name, disp);
                else                        ::sprintf_s(out, cap, "%s+0x%zX", name, rva);
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { /* fall through to module+RVA */ }
    }

    ::sprintf_s(out, cap, "%s+0x%zX", name, rva);
    return true;
}

void bpc::sym::ForEachModule(void (*fn)(const char*, const void*, size_t, void*), void* ctx)
{
    HMODULE mods[512];
    DWORD needed = 0;
    if (!::EnumProcessModules(::GetCurrentProcess(), mods, sizeof(mods), &needed)) return;

    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count && i < 512; ++i)
    {
        wchar_t wpath[MAX_PATH]{};
        ::GetModuleFileNameW(mods[i], wpath, MAX_PATH);
        const wchar_t* wname = ::wcsrchr(wpath, L'\\');
        wname = wname ? wname + 1 : wpath;

        char name[128];
        ::WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, sizeof(name), nullptr, nullptr);

        MODULEINFO mi{};
        ::GetModuleInformation(::GetCurrentProcess(), mods[i], &mi, sizeof(mi));
        fn(name, mods[i], mi.SizeOfImage, ctx);
    }
}

const void* bpc::sym::AddressOf(const char* symbol)
{
    if (!g_ready || !p_SymFromName || !symbol) return nullptr;

    alignas(8) uint8_t storage[sizeof(SYMBOL_INFO) + 1024]{};
    auto* si = reinterpret_cast<PSYMBOL_INFO>(storage);
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = 1023;

    /*
    Qualified first, and this is not a nicety: we run with SYMOPT_DEFERRED_LOADS, and under it
    dbghelp will NOT page in a module's symbols to satisfy a bare global name. SymFromAddr works
    regardless because the address names the module for it; SymFromName without a "module!"
    prefix simply misses, which is why ProcessLocalScriptFunction read as absent while sitting in
    the PDB at the right address the whole time. The bare form stays as the fallback for a symbol
    that lives somewhere other than the main module.
    */
    char qualified[512];
    ::sprintf_s(qualified, "%s!%s", MainModuleName(), symbol);
    if (LookUp(qualified, si)) return reinterpret_cast<const void*>(si->Address);

    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = 1023;
    if (LookUp(symbol, si)) return reinterpret_cast<const void*>(si->Address);
    return nullptr;
}
