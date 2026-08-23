/*
Platform_Win32.cpp

The Windows half of Platform.h, and the only file in the DLL that needs to know a module is a PE.
Everything here is a direct translation of the API into Win32; there is no policy in this file, so
a port is a matter of answering the same six questions on another OS rather than of understanding
anything about the tool.
*/

#include "Platform.h"

#include <windows.h>

namespace
{
    /* Header walk, shared by ModuleSize and Sections. Both want the NT headers and nothing else,
       and neither can be reached before the image is mapped, so no validation is worth its cost. */
    const IMAGE_NT_HEADERS* NtHeaders()
    {
        const uint8_t* base = bpc::plat::ModuleBase();
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        return reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    }

    DWORD FlagsFor(bpc::plat::SectionKind kind)
    {
        switch (kind)
        {
        case bpc::plat::SectionKind::Executable: return IMAGE_SCN_MEM_EXECUTE;
        case bpc::plat::SectionKind::Writable:   return IMAGE_SCN_MEM_WRITE;
        default:                                 return 0;
        }
    }

    // Committed, and not a page that faults or traps on touch. The shared half of the two probes.
    bool Live(const MEMORY_BASIC_INFORMATION& mbi)
    {
        return mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
    }
}

const uint8_t* bpc::plat::ModuleBase()
{
    static const uint8_t* b = reinterpret_cast<const uint8_t*>(::GetModuleHandleW(nullptr));
    return b;
}

size_t bpc::plat::ModuleSize()
{
    static size_t s = static_cast<size_t>(NtHeaders()->OptionalHeader.SizeOfImage);
    return s;
}

bool bpc::plat::BadRead(const void* p, size_t n)
{
    if (!p) return true;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!::VirtualQuery(p, &mbi, sizeof(mbi))) return true;
    if (!Live(mbi)) return true;
    const auto end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return reinterpret_cast<uintptr_t>(p) + n > end;
}

bool bpc::plat::IsExecutable(const void* p)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!p || !::VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (!Live(mbi)) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

size_t bpc::plat::Sections(Section* out, size_t cap, SectionKind kind)
{
    if (!out || !cap) return 0;

    const uint8_t* base = ModuleBase();
    const auto* nt = NtHeaders();
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    const DWORD mask = FlagsFor(kind);

    size_t n = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && n < cap; ++i, ++sec)
    {
        if (mask && !(sec->Characteristics & mask)) continue;
        out[n++] = { base + sec->VirtualAddress, sec->Misc.VirtualSize };
    }
    return n;
}

const void* bpc::plat::ImportedFunction(const wchar_t* dll, const char* fn)
{
    HMODULE m = ::GetModuleHandleW(dll);
    return m ? reinterpret_cast<const void*>(::GetProcAddress(m, fn)) : nullptr;
}
