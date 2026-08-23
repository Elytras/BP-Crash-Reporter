/*
Platform_Posix.cpp

Unimplemented. This file exists to mark the seam, not to suggest a Linux build is close.

Platform.h is the entire OS surface of the *resolution* layer, and these six functions are all of
it -- so a port starts by answering them over ELF and /proc/self/maps rather than PE and
VirtualQuery, which is a genuinely small job. What is not small is everything around it: the
handler installs a vectored exception handler, the symbol layer is dbghelp, the interceptor is
MinHook detouring x86-64 prologues, and the loader injects with CreateRemoteThread. None of that
has an abstraction here, because writing one against a single implementation would be inventing an
interface out of guesses about the second one.

So the stubs below let the layer compile and keep the boundary honest and visible; they do not let
the tool build or run. CMake refuses a non-Windows configure for that reason -- see CMakeLists.txt
-- and this file is not in any target today. Read it as documentation of where a port would begin.
*/

#include "Platform.h"

const uint8_t* bpc::plat::ModuleBase() { return nullptr; }
size_t         bpc::plat::ModuleSize() { return 0; }

/* Nothing is readable and nothing is code, which is the safe direction to be wrong in: every
   caller treats these as a veto, so a stubbed layer resolves nothing rather than dereferencing
   garbage. */
bool bpc::plat::BadRead(const void*, size_t)     { return true; }
bool bpc::plat::IsExecutable(const void*)        { return false; }

size_t bpc::plat::Sections(Section*, size_t, SectionKind) { return 0; }

const void* bpc::plat::ImportedFunction(const wchar_t*, const char*) { return nullptr; }
