# Cross-compile real Windows PE binaries from Linux with clang against the mingw-w64 sysroot.
#
# Plain GCC mingw cannot build this codebase: __try/__except (SEH) is a Microsoft extension GCC
# does not implement. Clang does, against the mingw-w64 (GNU) environment, given
# -fms-extensions (parses __try/__except) and -fasync-exceptions (makes __except actually catch
# hardware faults like the null-deref this tool exists to report -- without it only C++ throw
# unwinds are caught, which is not what /EHa gets you on MSVC either).
#
# Verified against Wine 9.0 / clang 18 / mingw-w64 13.2 before this file was written: a
# throwaway __try/__except around a null-deref, plus sprintf_s, both compile and behave
# correctly when run under `wine`.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

set(BPC_TARGET_TRIPLE "x86_64-w64-mingw32")
set(CMAKE_C_COMPILER_TARGET   ${BPC_TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${BPC_TARGET_TRIPLE})

# -fms-extensions (parses __try/__except) is safe and needed globally -- mingw's own headers
# lean on other MS extensions throughout. -fasync-exceptions (makes __except actually catch a
# hardware fault, not just a C++ throw) is NOT applied globally: it crashes clang 18's optimizer
# (a BranchProbabilityInfo/AlwaysInliner crash, reproduced even at -O0, on Endpoint.cpp -- a file
# with no __try/__except in it at all) when combined with this codebase's template-heavy code.
# CMakeLists.txt instead adds -fasync-exceptions per-file, only on the three translation units
# that actually contain __try/__except (DllMain.cpp, Dump.cpp, Symbols.cpp).
set(CMAKE_C_FLAGS_INIT   "-fms-extensions")
set(CMAKE_CXX_FLAGS_INIT "-fms-extensions")

set(CMAKE_FIND_ROOT_PATH "/usr/${BPC_TARGET_TRIPLE}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_RC_FLAGS "--target=pe-x86-64")
