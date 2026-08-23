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
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
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
target_include_directories(BPCrashHandler PRIVATE ${minhook_SOURCE_DIR}/include)
target_compile_options(BPCrashHandler PRIVATE /EHa)   # __try/__except alongside C++ objects
# PSAPI_VERSION=2 routes EnumProcessModules to kernel32, so the import table stays KERNEL32-only.
target_compile_definitions(BPCrashHandler PRIVATE PSAPI_VERSION=2)
# Picked up by version.rc as well as the C++: the DLL must not claim to be bpcrash.exe.
target_compile_definitions(BPCrashHandler PRIVATE BPC_DLL)

add_executable(bpcrash src/loader/main.cpp src/version.rc)
set_target_properties(bpcrash PROPERTIES OUTPUT_NAME "bpcrash")
add_dependencies(bpcrash BPCrashHandler)

if(BPC_EMBED_DLL)
    # rc.exe finds `bpcrash.dll` through its include path, pointed at the DLL's output dir.
    target_sources(bpcrash PRIVATE src/loader/payload.rc)
    target_include_directories(bpcrash PRIVATE $<TARGET_FILE_DIR:BPCrashHandler>)
    # rc.exe cannot see that the payload changed, so relink the exe whenever the DLL does.
    set_source_files_properties(src/loader/payload.rc
        PROPERTIES OBJECT_DEPENDS $<TARGET_FILE:BPCrashHandler>)
endif()

# Everything ships as one folder: exe plus cfg.
configure_file(bpcrash.cfg ${CMAKE_BINARY_DIR}/bpcrash.cfg COPYONLY)

# The one runnable check. Pure decoders only, no game required.
add_executable(selftest tests/selftest.cpp src/dll/Symbols.cpp src/dll/Platform_Win32.cpp)
target_include_directories(selftest PRIVATE ${minhook_SOURCE_DIR}/include)
target_compile_definitions(selftest PRIVATE PSAPI_VERSION=2)
set_target_properties(selftest PROPERTIES LINK_FLAGS "/DEBUG")   # give it a PDB to find

# Harness for "the DLL loaded but nothing happened" failures. Not part of the shipped set.
add_executable(hostload tests/hostload.cpp)
