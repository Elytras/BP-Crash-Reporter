cmake_minimum_required(VERSION 3.21)
project(BPCrashHandler CXX C RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows only, and the failure should be a sentence rather than a wall of missing headers. The
# resolution layer's OS surface is abstracted (Platform.h, with an unimplemented Platform_Posix.cpp
# marking the seam), but the handler, symbols, interceptor and loader are still Win32 outright.
if(NOT WIN32)
    message(FATAL_ERROR
        "BPCrashHandler builds on Windows x64 only. It injects into Windows PE processes using "
        "SEH, dbghelp and MinHook; src/dll/Platform_Posix.cpp shows where a port would start.")
endif()

# Static CRT everywhere. The machine this runs on is someone else's, and a missing VC redist
# would be a support burden for a tool meant to be dropped next to a game and run.
#
# CMAKE_MSVC_RUNTIME_LIBRARY only applies to an MSVC-ABI compiler (real MSVC, or clang-cl). The
# Linux cross build uses clang in its GNU driver mode against the mingw-w64 sysroot instead (see
# cmake/linux-mingw-clang.toolchain.cmake -- MSVC-cl mode cannot parse __try/__except the way
# this codebase needs); there, the equivalent is linking libgcc/libstdc++/winpthread statically.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()
set(VCPKG_APPLOCAL_DEPS OFF)   # nothing here links a vcpkg DLL; stop the deploy step guessing

# A PE that carries another PE in its resources, drops it, and loads it into a third process has
# the shape of a dropper, and AV heuristics score it accordingly. Shipping the DLL as a separate
# file removes that one signal. The default stays ON because one file is nicer to hand out.
option(BPC_EMBED_DLL "Embed the DLL in the loader exe" ON)

# MinHook is the only dependency, and it is fetched rather than vendored.
include(FetchContent)
FetchContent_Declare(minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        v1.3.3)
FetchContent_MakeAvailable(minhook)

# v1.3.3 ships no CMakeLists, so its five C files are compiled straight into the DLL.
file(GLOB MINHOOK_SRC ${minhook_SOURCE_DIR}/src/*.c ${minhook_SOURCE_DIR}/src/hde/*.c)

add_library(BPCrashHandler SHARED
    src/dll/DllMain.cpp
    src/dll/Endpoint.cpp
    src/dll/Interceptor.cpp
    src/dll/Dump.cpp
    src/dll/Symbols.cpp
    src/dll/Platform_Win32.cpp
    src/version.rc
    ${MINHOOK_SRC})
set_target_properties(BPCrashHandler PROPERTIES OUTPUT_NAME "bpcrash")
# The mingw/GNU toolchain's default shared-library prefix is "lib" (a Linux .so convention);
# real Windows DLLs don't carry one, and the loader looks for an exact "bpcrash.dll" beside it.
set_target_properties(BPCrashHandler PROPERTIES PREFIX "")
target_include_directories(BPCrashHandler PRIVATE ${minhook_SOURCE_DIR}/include)
# __try/__except alongside C++ objects.
if(MSVC)
    target_compile_options(BPCrashHandler PRIVATE /EHa)
else()
    # -fasync-exceptions only on the files that actually use __try/__except -- applying it
    # module-wide crashes clang's optimizer on this codebase (see the toolchain file).
    set_source_files_properties(src/dll/DllMain.cpp src/dll/Dump.cpp src/dll/Symbols.cpp
        PROPERTIES COMPILE_OPTIONS "-fasync-exceptions")
endif()
# PSAPI_VERSION=2 routes EnumProcessModules to kernel32, so the import table stays KERNEL32-only.
target_compile_definitions(BPCrashHandler PRIVATE PSAPI_VERSION=2)
# Picked up by version.rc as well as the C++: the DLL must not claim to be bpcrash.exe.
target_compile_definitions(BPCrashHandler PRIVATE BPC_DLL)

add_executable(bpcrash src/loader/main.cpp src/version.rc)
set_target_properties(bpcrash PROPERTIES OUTPUT_NAME "bpcrash")
add_dependencies(bpcrash BPCrashHandler)
# wmain (here and in hostload) needs mingw's wide-entry console CRT stub; without -municode the
# linker reaches for WinMain instead and fails. No-op / unrecognised on a real MSVC link.
if(NOT MSVC)
    target_link_options(bpcrash PRIVATE -municode -mconsole)
endif()

if(BPC_EMBED_DLL)
    # rc.exe finds `bpcrash.dll` through its include path, pointed at the DLL's output dir.
    target_sources(bpcrash PRIVATE src/loader/payload.rc)
    target_include_directories(bpcrash PRIVATE $<TARGET_FILE_DIR:BPCrashHandler>)
    # add_dependencies(bpcrash BPCrashHandler) above only orders BPCrashHandler before the *link*
    # of bpcrash.exe; nothing stops Ninja scheduling the payload.rc compile (which needs
    # bpcrash.dll to already exist, since rc.exe literally opens it to embed it) in parallel with,
    # or before, BPCrashHandler's own build -- so a clean parallel build fails intermittently with
    # rc.exe reporting "can't open file bpcrash.dll". OBJECT_DEPENDS fixes that, but only with a
    # literal path: $<TARGET_FILE:BPCrashHandler> resolves fine elsewhere in this file (see the
    # include directory above) but is never substituted when used in OBJECT_DEPENDS together with
    # an RC source on this project's Ninja + windres combination -- it is emitted into build.ninja
    # as the literal string "$<TARGET_FILE:BPCrashHandler>", which Ninja then reports as a
    # permanently missing file with no rule to build it, failing every build, not just parallel
    # ones. BPCrashHandler has no per-config output subdirectory here (single-config Ninja, no
    # CMAKE_RUNTIME_OUTPUT_DIRECTORY override), so the literal path below is exact.
    set_source_files_properties(src/loader/payload.rc
        PROPERTIES OBJECT_DEPENDS "${CMAKE_BINARY_DIR}/bpcrash.dll")
endif()

# Everything ships as one folder: exe plus cfg.
configure_file(bpcrash.cfg ${CMAKE_BINARY_DIR}/bpcrash.cfg COPYONLY)

# The one runnable check. Pure decoders only, no game required.
add_executable(selftest tests/selftest.cpp src/dll/Symbols.cpp src/dll/Platform_Win32.cpp)
target_include_directories(selftest PRIVATE ${minhook_SOURCE_DIR}/include)
target_compile_definitions(selftest PRIVATE PSAPI_VERSION=2)
if(MSVC)
    set_target_properties(selftest PROPERTIES LINK_FLAGS "/DEBUG")   # give it a PDB to find
else()
    set_source_files_properties(src/dll/Symbols.cpp PROPERTIES COMPILE_OPTIONS "-fasync-exceptions")
endif()

# Harness for "the DLL loaded but nothing happened" failures. Not part of the shipped set.
add_executable(hostload tests/hostload.cpp)
if(NOT MSVC)
    target_link_options(hostload PRIVATE -municode -mconsole)
endif()
