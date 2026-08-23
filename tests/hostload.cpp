/*
hostload.cpp

Loads the DLL into a plain process and watches what it does. This is not a unit test but a harness
for the "no report was written" class of failure, where the question is whether the DLL's worker
thread reaches the end of its startup at all. There is no engine here, so Endpoint::Init is
expected to fail its GObjects poll; what matters is that it still finishes, still arms, and still
writes a report saying so.

  hostload.exe <path-to-bpcrash.dll> [--crash|--overflow]

--crash triggers an access violation afterwards and --overflow runs off the end of the stack, to
exercise the handler itself. Either one shortens the wait, since the handler is armed first and
neither needs the engine.
*/

#include <cstdio>
#include <windows.h>

namespace
{
    /*
    Runs the stack out, to give the DLL's handler a stack overflow to report. `pad` keeps each
    frame large enough to reach the guard page in a reasonable number of calls, and the volatile
    sink stops it being elided.

    Optimization is off for this one function because at /O2 the self-call is a tail call: the
    compiler folds the recursion into a loop in a single frame, which spins forever instead of
    overflowing, and the harness then tests nothing at all.
    */
    volatile int g_sink = 0;

#pragma optimize("", off)
    void Overflow(int depth)
    {
        volatile char pad[4096];
        pad[0] = static_cast<char>(depth);
        g_sink += pad[0];
        Overflow(depth + 1);
    }
#pragma optimize("", on)
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) { std::printf("usage: hostload <dll> [--crash|--overflow [--vm]]\n"); return 2; }

    const bool crash = argc > 2 && ::wcscmp(argv[2], L"--crash") == 0;
    const bool overflow = argc > 2 && ::wcscmp(argv[2], L"--overflow") == 0;

    const DWORD t0 = ::GetTickCount();
    std::printf("loading %ls ...\n", argv[1]);

    HMODULE m = ::LoadLibraryW(argv[1]);
    if (!m) { std::printf("LoadLibrary failed: %lu\n", ::GetLastError()); return 1; }
    std::printf("mapped at %p after %lu ms\n", m, ::GetTickCount() - t0);

    // The worker runs on its own thread, so wait longer than Endpoint's own poll timeout.
    const int seconds = (crash || overflow) ? 15 : 150;
    for (int i = 0; i < seconds; ++i)
    {
        ::Sleep(1000);
        if (i % 10 == 9) std::printf("  ... %d s\n", i + 1);
    }

    if (crash)
    {
        std::printf("triggering an access violation\n");
        *reinterpret_cast<volatile int*>(0x1234) = 1;
    }
    if (overflow)
    {
        /*
        `--overflow-vm` mimics a thread that has been through the ProcessInternal hook, which
        reserves 64 KB below the guard page so the handler has room to run. Plain `--overflow` is
        the bare case, on a thread that never entered the VM.
        */
        if (argc > 3 && ::wcscmp(argv[3], L"--vm") == 0)
        {
            ULONG bytes = 64 * 1024;
            ::SetThreadStackGuarantee(&bytes);
            std::printf("stack guarantee set, running the stack out\n");
        }
        else
        {
            std::printf("running the stack out\n");
        }
        Overflow(0);
    }

    std::printf("done after %lu ms\n", ::GetTickCount() - t0);
    return 0;
}
