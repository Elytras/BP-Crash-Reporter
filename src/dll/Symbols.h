#pragma once
/*
Symbols.h

Turns native addresses into names, for every module in the process. Used by Dump.cpp for the
faulting instruction and the native call stack, and by Endpoint.cpp to look up
ProcessLocalScriptFunction by name.

The games ship no PDBs, but generated ones sit next to the exe (binfold writes a guessed-name PDB
from a matched database). Those do not carry the exe's CodeView signature, so dbghelp refuses them
unless `SYMOPT_LOAD_ANYTHING` is set.

The scope is the whole process rather than just the game module. If another injected DLL is on the
stack (a mod loader, an overlay, an anti-cheat, your own tooling) its frames get named from its own
PDB, which is usually the fastest way to see that the crash was not the game's fault.

Two things keep this out of the crash handler's way:

  * dbghelp allocates, so it is initialised at load time and the main module's symbols are forced
    resident then. The fault path is never the first thing to parse a 20 MB PDB.
  * dbghelp.dll is loaded explicitly from System32. A plain import would go through the normal
    search order, and UE game folders not infrequently ship their own dbghelp.dll.

Symbols are optional throughout. If none of this works, every caller falls back to module+RVA.
*/

#include <cstddef>

namespace bpc::sym
{
    // Load dbghelp, enumerate modules, warm the main module. Returns false if symbols are off.
    bool Init();
    bool Ready();

    // One-line status for the dump header.
    const char* Status();

    /*
    "Module.dll!Class::Method+0x1F", or "Module.dll+0x12345" with no symbol for that address.
    False if the address is in no loaded module at all. Never throws; safe on garbage pointers.
    */
    bool Resolve(const void* addr, char* out, size_t cap);

    /*
    Reverse lookup, from a symbol name to its address, or null. This only works with a real PDB,
    so every caller needs a fallback. When one is present it beats any signature, being the
    linker's own answer rather than a guess about instruction bytes.
    */
    const void* AddressOf(const char* symbol);

    // Pick up modules injected after Init. Cheap enough to call once per crash.
    void Refresh();

    // Every loaded module, one "name  base  size" line each, into the dump.
    void ForEachModule(void (*fn)(const char* name, const void* base, size_t size, void* ctx), void* ctx);
}
