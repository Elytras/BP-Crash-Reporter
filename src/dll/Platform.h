#pragma once
/*
Platform.h

The process and module primitives every resolver in Endpoint.cpp is built from: section walks,
pattern scans, readability probes, and relative-operand decoding.

This header is the API and carries no OS headers of its own -- <cstdint>, <cstring> and
<string_view> are the whole dependency list. Everything that actually needs the operating system
is declared here and defined in one Platform_<os>.cpp; everything that is pure arithmetic over
bytes (the pattern scanner, the x86-64 operand decoders) stays inline here, because it is the same
code everywhere and there is no reason to pay a call for it.

That split is why <windows.h> no longer arrives through this header, and it used to arrive widely:
Bytecode.h and NamePool.h both include this file, so every translation unit downstream of them got
it too. The macro pollution that came with it -- `min`, `max`, `GetObject` and friends, over
headers like Ue.h that define engine types -- was a standing hazard, and keeping it out is most of
the practical benefit here.

Nothing in the OS layer allocates. It is used by the resolution phase and, indirectly, by the crash
handler, and a crash handler that reaches for the heap is a crash handler that hangs on a corrupted
one. That is why the pattern scanner parses into a stack buffer and why Sections() fills a caller's
array instead of returning a container.

Modelled on Dumper-7's Platform layer, cut down to the x86-64 subset this tool needs.
*/

#include <cstdint>
#include <cstring>
#include <string_view>

namespace bpc::plat
{
    // ---------------------------------------------------------------------------------------
    // The OS layer. Declared here, defined once per platform; see Platform_Win32.cpp.
    // ---------------------------------------------------------------------------------------

    struct Section { const uint8_t* start = nullptr; size_t size = 0; };

    /*
    Which sections of the main module a walk should visit. This replaces the raw IMAGE_SCN_*
    mask the walk used to take, which was the one place a PE constant leaked into the API and
    forced <windows.h> on every caller.
    */
    enum class SectionKind { Any, Executable, Writable };

    // Base address and mapped size of the main module (the game exe, not this DLL).
    const uint8_t* ModuleBase();
    size_t         ModuleSize();

    /*
    Readability probe, used before every read of game memory. It asks the OS about the mapping
    rather than trying the read behind a handler, because resolution walks millions of candidate
    addresses and per-read fault handling would dominate load time. Nothing is cached, since page
    protection can change under us.
    */
    bool BadRead(const void* p, size_t n = 8);

    // Committed and executable. The cheap first filter when scanning a stack for code.
    bool IsExecutable(const void* p);

    /*
    Fill `out` with the main module's sections matching `kind`, in image order, and return how
    many were written (capped at `cap`). Prefer ForEachSection below; this is the primitive it is
    built on, split out only so the walk itself can stay a template in this header.
    */
    size_t Sections(Section* out, size_t cap, SectionKind kind);

    // Address of an already-loaded module's export, or null. Never loads anything.
    const void* ImportedFunction(const wchar_t* dll, const char* fn);

    // ---------------------------------------------------------------------------------------
    // Portable from here down: byte arithmetic only, no OS call except through the above.
    // ---------------------------------------------------------------------------------------

    inline bool InModule(const void* p)
    {
        const auto a = reinterpret_cast<uintptr_t>(p);
        const auto lo = reinterpret_cast<uintptr_t>(ModuleBase());
        return a >= lo && a < lo + ModuleSize();
    }

    inline uintptr_t Rva(const void* p)
    {
        return reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(ModuleBase());
    }

    /* No real image comes close, and the walk below wants a stack array rather than a heap one. */
    inline constexpr size_t kMaxSections = 32;

    // Every matching section; `fn` returns false to stop.
    template <class Fn>
    void ForEachSection(Fn&& fn, SectionKind kind = SectionKind::Any)
    {
        Section s[kMaxSections];
        const size_t n = Sections(s, kMaxSections, kind);
        for (size_t i = 0; i < n; ++i)
            if (!fn(s[i])) return;
    }

    // IDA-style pattern scan: "48 8D 0D ? ? ? ? E8", where '?' or '??' is a wildcard byte.

    inline int HexNib(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    struct PatternByte { uint8_t value; bool wild; };

    // Decode into `out`; returns the byte count, or 0 on a malformed / oversized pattern.
    inline size_t ParsePattern(std::string_view sig, PatternByte* out, size_t cap)
    {
        size_t n = 0;
        for (size_t i = 0; i < sig.size(); )
        {
            if (sig[i] == ' ') { ++i; continue; }
            if (n >= cap) return 0;
            if (sig[i] == '?')
            {
                out[n++] = { 0, true };
                i += (i + 1 < sig.size() && sig[i + 1] == '?') ? 2 : 1;
                continue;
            }
            const int hi = HexNib(sig[i]);
            const int lo = (i + 1 < sig.size()) ? HexNib(sig[i + 1]) : -1;
            if (hi < 0 || lo < 0) return 0;
            out[n++] = { static_cast<uint8_t>(hi * 16 + lo), false };
            i += 2;
        }
        return n;
    }

    inline const uint8_t* FindPatternIn(const uint8_t* start, size_t size, std::string_view sig)
    {
        PatternByte pat[64];
        const size_t n = ParsePattern(sig, pat, 64);
        if (!n || size < n) return nullptr;
        for (size_t i = 0; i + n <= size; ++i)
        {
            size_t j = 0;
            for (; j < n; ++j)
                if (!pat[j].wild && start[i + j] != pat[j].value) break;
            if (j == n) return start + i;
        }
        return nullptr;
    }

    // Scan the main module's executable sections. `after` resumes past a previous hit.
    inline const uint8_t* FindPattern(std::string_view sig, const uint8_t* after = nullptr)
    {
        const uint8_t* hit = nullptr;
        bool reached = (after == nullptr);
        ForEachSection([&](Section s)
        {
            const uint8_t* from = s.start;
            size_t size = s.size;
            if (!reached)
            {
                if (after < s.start || after >= s.start + s.size) return true;   // earlier section
                reached = true;
                from = after + 1;
                size = static_cast<size_t>(s.start + s.size - from);
            }
            if (const uint8_t* h = FindPatternIn(from, size, sig)) { hit = h; return false; }
            return true;
        }, SectionKind::Executable);
        return hit;
    }

    // Byte-array match with -1 as wildcard, searched forward from `at` over `range` bytes.
    inline bool FindBytesInRange(const int* bytes, size_t count, const uint8_t* at, size_t range)
    {
        if (!at || BadRead(at, 1)) return false;
        for (size_t i = 0; i + count <= range; ++i)
        {
            size_t j = 0;
            for (; j < count; ++j)
                if (bytes[j] != -1 && at[i + j] != static_cast<uint8_t>(bytes[j])) break;
            if (j == count) return true;
        }
        return false;
    }

    // x86-64 relative operand resolution.

    // RIP-relative operand: `opLen` bytes precede the disp32, `insnLen` is the whole instruction.
    inline uintptr_t RipTarget(const uint8_t* at, int opLen, int insnLen)
    {
        const int32_t disp = *reinterpret_cast<const int32_t*>(at + opLen);
        return reinterpret_cast<uintptr_t>(at) + insnLen + disp;
    }

    inline uintptr_t CallTarget(const uint8_t* at)                 // E8 rel32
    {
        return (*at == 0xE8) ? RipTarget(at, 1, 5) : 0;
    }

    inline uintptr_t IndirectCallSlot(const uint8_t* at)           // FF 15 [rip+disp32] -> IAT slot
    {
        return RipTarget(at, 2, 6);
    }

    /*
    Walk a vtable until an entry stops looking like code in this module. `pred(fnAddr, idx)`
    returns true to accept. Returns the accepted index, or -1.
    */
    template <class Pred>
    inline int IterateVTable(void** vft, Pred&& pred, int maxIdx = 0x200)
    {
        if (!vft || BadRead(vft)) return -1;
        for (int i = 0; i < maxIdx; ++i)
        {
            if (BadRead(vft + i)) return -1;
            void* fn = vft[i];
            if (!fn || !InModule(fn)) return -1;
            if (pred(reinterpret_cast<const uint8_t*>(fn), i)) return i;
        }
        return -1;
    }
}
