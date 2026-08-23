#pragma once
/*
NamePool.h

Turns an FName into text without calling the engine, for every name that appears in a report.

The obvious implementation, `FName::ToString`, allocates an FString and takes the pool's RW lock.
Neither is available to us: this runs inside a crash handler, on a thread that may already hold
that lock, with a heap that may be the thing that is corrupt. So we decode the pool by hand.

Layout (UE4.23+ FNameEntryAllocator), checked at init against the always-present "None":

    +0x00  FRWLock
    +0x08  uint32 CurrentBlock
    +0x0C  uint32 CurrentByteCursor
    +0x10  uint8* Blocks[8192]

  ComparisonIndex -> block = idx >> 16, offset = idx & 0xFFFF, entry = Blocks[block] + offset*2
  FNameEntry      -> uint16 header { bit0 = wide, bits 6.. = length }, then the characters
*/

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "Endpoint.h"
#include "Platform.h"
#include "Ue.h"

namespace bpc::names
{
    inline bool      g_ok = false;
    inline uint8_t** g_blocks = nullptr;
    inline uint8_t*  g_pool = nullptr;
    inline uint32_t  g_blockCount = 0;   // only a seed: the live count is read per lookup, below

    // Raw entry text into `out` (always NUL-terminated). False = unreadable / not a sane entry.
    inline bool RawEntry(int32_t idx, char* out, size_t cap)
    {
        if (!g_ok || idx < 0 || cap == 0) return false;
        const uint32_t block = static_cast<uint32_t>(idx) >> 16;
        const uint32_t off = static_cast<uint32_t>(idx) & 0xFFFF;

        /* We read CurrentBlock live rather than caching it at bind time. The pool grows for the
           whole session, since every asset load interns more names, so a count captured at
           startup would reject everything allocated afterwards -- which is most of what a crash
           report needs to name. */
        if (plat::BadRead(g_pool + 0x08, 4)) return false;
        const uint32_t live = *reinterpret_cast<const uint32_t*>(g_pool + 0x08);
        if (block > live || block >= 8192) return false;

        uint8_t* base = g_blocks[block];
        if (plat::BadRead(base, 4)) return false;
        const uint8_t* entry = base + static_cast<size_t>(off) * 2;
        if (plat::BadRead(entry, 4)) return false;

        const uint16_t header = *reinterpret_cast<const uint16_t*>(entry);
        const bool wide = (header & 1) != 0;
        const uint32_t len = header >> 6;
        if (len == 0 || len > 1024) return false;

        const size_t bytes = wide ? len * 2 : len;
        if (plat::BadRead(entry + 2, bytes)) return false;

        const size_t n = (len < cap - 1) ? len : cap - 1;
        if (wide)
        {
            const auto* w = reinterpret_cast<const wchar_t*>(entry + 2);
            for (size_t i = 0; i < n; ++i) out[i] = (w[i] < 0x80) ? static_cast<char>(w[i]) : '?';
        }
        else
        {
            ::memcpy(out, entry + 2, n);
        }
        out[n] = '\0';
        return true;
    }

    // Full FName including the `_N` suffix. Never throws, never allocates, never blocks.
    inline void Decode(ue::FName n, char* out, size_t cap)
    {
        if (!RawEntry(n.ComparisonIndex, out, cap))
        {
            // Carry the index, so which name failed is answerable from the report alone.
            ::sprintf_s(out, cap, "<name?#%X>", n.ComparisonIndex);
            return;
        }
        if (n.Number > 0)
        {
            const size_t l = ::strlen(out);
            if (l + 12 < cap) ::sprintf_s(out + l, cap - l, "_%d", n.Number - 1);
        }
    }

    // Convenience for UObject / FField, both of which just carry an FName.
    inline void Of(const ue::UObject* o, char* out, size_t cap)
    {
        if (plat::BadRead(o, sizeof(ue::UObject))) { ::strncpy_s(out, cap, "<obj?>", _TRUNCATE); return; }
        Decode(o->Name, out, cap);
    }
    inline void Of(const ue::FField* f, char* out, size_t cap)
    {
        if (plat::BadRead(f, sizeof(ue::FField))) { ::strncpy_s(out, cap, "<field?>", _TRUNCATE); return; }
        Decode(f->Name, out, cap);
    }

    /*
    Full outer chain, e.g. "/Game/Enemies/BP_Grunt.BP_Grunt_C:ExecuteUbergraph". Walked outer-first
    into a fixed buffer, with no allocation.
    */
    inline void PathOf(const ue::UObject* o, char* out, size_t cap)
    {
        const ue::UObject* chain[16];
        int n = 0;
        for (const ue::UObject* p = o; p && n < 16; p = p->Outer)
        {
            if (plat::BadRead(p, sizeof(ue::UObject))) break;
            chain[n++] = p;
        }
        out[0] = '\0';
        size_t used = 0;
        for (int i = n - 1; i >= 0 && used + 2 < cap; --i)
        {
            if (used) { out[used++] = (i == 0) ? ':' : '.'; out[used] = '\0'; }
            char part[256];
            Of(chain[i], part, sizeof(part));
            ::strncat_s(out, cap, part, _TRUNCATE);
            used = ::strlen(out);
        }
    }

    /*
    Bind to the pool the endpoint resolved, then check the layout by decoding index 0, which is
    "None" in every UE4 build. If that fails we leave names off rather than read garbage into a
    crash report.
    */
    inline bool Init()
    {
        uint8_t* pool = endpoint::Get().namePool;
        if (!pool || plat::BadRead(pool, 0x18)) return false;

        g_pool = pool;
        g_blockCount = *reinterpret_cast<uint32_t*>(pool + 0x08);
        g_blocks = reinterpret_cast<uint8_t**>(pool + 0x10);
        if (g_blockCount > 8192) { g_blocks = nullptr; g_pool = nullptr; return false; }

        g_ok = true;
        char probe[16];
        if (RawEntry(0, probe, sizeof(probe)) && ::strcmp(probe, "None") == 0) return true;

        g_ok = false;
        return false;
    }
}
