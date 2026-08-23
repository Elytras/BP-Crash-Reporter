/*
DllMain.cpp

Startup for the injected DLL. Nothing here is interactive: no console, no window, no IPC. The
only files produced are bpcrash_status.txt (one line per startup phase), the load-time self-test
report, and a crash report if the game faults. All three are written beside this DLL.

The order of the steps in Startup() matters. We arm the crash handler before resolving symbols or
the engine, because anything that runs ahead of Arm() is a window in which a crash produces
nothing at all.
*/

#include <windows.h>

#include <cstdio>

#include "Dump.h"
#include "Endpoint.h"
#include "Interceptor.h"
#include "NamePool.h"
#include "Symbols.h"

HMODULE g_SelfModule = nullptr;   // read by Dump.cpp to place every artifact next to this DLL

namespace
{
    void Startup()
    {
        using namespace bpc;

        dump::Breadcrumb("loaded");

        /* From here on a crash produces a report. It may be a degraded one -- no symbols, no
           Blueprint frames yet -- but never nothing at all. */
        dump::Arm();
        dump::Breadcrumb("crash handler armed");

        /* Symbols come before the engine wait, because with a PDB present the endpoint can
           resolve ProcessLocalScriptFunction by name instead of decoding bytes for it. This step
           takes about a second; the engine wait below is the slow one. */
        sym::Init();
        dump::Breadcrumb(sym::Status());

        /* A report BEFORE the wait. The wait can last as long as the game takes to boot, and a
           crash during it used to leave no self-test at all -- the one artifact that says how far
           startup got. The final one below supersedes this. */
        dump::WriteNow("load-time self test (armed, engine not resolved yet)");

        /*
        No deadline, by design. A game can take minutes to reach the engine -- a cold shader
        cache, a slow disk, a long intro -- and a timeout cannot tell that apart from a broken
        scan, so the old 120s bound gave up on the first case and said nothing useful about the
        second. Instead: retry while the answer is "not yet", and stop only on a verdict the
        endpoint can actually prove (see endpoint::Progress).
        */
        endpoint::Progress p = endpoint::Progress::NotYet;
        for (unsigned attempt = 1; ; ++attempt)
        {
            p = endpoint::TryInit();
            if (p != endpoint::Progress::NotYet) break;

            if (attempt == 1 || attempt % 20 == 0)
            {
                char note[160];
                ::sprintf_s(note, "waiting for the engine (attempt %u, %d objects)",
                            attempt, endpoint::NumObjects());
                dump::Breadcrumb(note);
            }

            /*
            Back off, because "retry forever" and "scan forever" are not the same promise. Each
            attempt sweeps every writable section looking for the object array, so a host that
            never brings up an engine -- the test harness, or an injection into the wrong process
            -- would otherwise burn a core for the life of the process. Quick while a game is
            plausibly still booting, then idle.
            */
            const DWORD waitMs = attempt < 40 ? 250 : (attempt < 200 ? 1000 : 5000);
            ::Sleep(waitMs);
        }

        const bool ok = (p == endpoint::Progress::Ready);
        dump::Breadcrumb(ok ? "endpoint resolved"
                            : "endpoint REJECTED -- resolution is broken on this build (see the self-test report)");

        names::Init();
        dump::Breadcrumb("name pool bound");

        if (ok)
        {
            interceptor::Install();
            dump::Breadcrumb("blueprint hooks installed");
        }

        /* The self-test report is written whether or not resolution succeeded, so a failure
           shows up as a file on disk rather than as silence. */
        dump::WriteNow(ok ? "load-time self test (armed)"
                          : "load-time self test (NOT ARMED -- resolution rejected)");
        dump::Breadcrumb("self-test report written -- startup complete");
    }

    DWORD WINAPI Worker(LPVOID)
    {
        // A fault during startup should leave a trace rather than a thread that vanishes.
        __try { Startup(); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            bpc::dump::Breadcrumb("STARTUP FAULTED -- the phase above is where it died");
        }
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_SelfModule = module;
        ::DisableThreadLibraryCalls(module);
        // The actual work runs on its own thread, off the loader lock.
        ::CloseHandle(::CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr));
    }
    return TRUE;
}
