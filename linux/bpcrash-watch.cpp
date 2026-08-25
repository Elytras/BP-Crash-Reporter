/*
bpcrash-watch.cpp

Linux-native companion to the Windows loader (src/loader/main.cpp), for running that loader
under Proton without deadlocking Steam.

Under Proton, bpcrash.exe is itself a Wine client: it connects to the target's wineserver to do
its watching and injecting. wineserver -- and, with it, Steam's own idea of whether that game is
still "Running" and relaunchable -- stays alive as long as any client is still attached. The
Windows loader is designed to stay attached forever on purpose (so a game restart doesn't need
the loader restarted too), which is exactly right on real Windows and exactly wrong here: it
quietly wedges Steam's UI long after the game and its crash dialog are gone, because from
wineserver's point of view the session never ended.

This tool is the fix: it is a genuine native Linux process that never touches wineserver at all
while idle -- it only watches /proc, which costs Wine nothing -- and, the moment the target
process appears, launches `wine bpcrash.exe --once` just long enough to inject and disconnect.
The DLL and the injection logic (CreateRemoteThread + LoadLibraryW, run for real inside Wine) are
completely unchanged; this only replaces the "stay attached and keep watching" outer loop with
one that lives outside Wine's world entirely.

Build (this one file, no dependencies, whatever C++20 host compiler you already have):
    g++ -O2 -std=c++20 -o bpcrash-watch bpcrash-watch.cpp

Usage:
    bpcrash-watch <path-to-wine> <path-to-bpcrash.exe>

WINEPREFIX must already be set in the environment (same as running bpcrash.exe by hand); it is
inherited by the `wine` child unchanged. The target process name comes from bpcrash.cfg next to
bpcrash.exe, exactly as the Windows loader itself reads it.
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>
#include <fstream>
#include <filesystem>

#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>

namespace fs = std::filesystem;

namespace
{
    std::string Trim(std::string s)
    {
        const auto ws = " \t\r\n";
        const auto a = s.find_first_not_of(ws);
        if (a == std::string::npos) return {};
        return s.substr(a, s.find_last_not_of(ws) - a + 1);
    }

    // Same one-key `key = value` config as the Windows loader; kept independent on purpose
    // rather than shared, since the two never build in the same toolchain.
    std::string ReadConfig(const fs::path& file, const std::string& key)
    {
        std::ifstream in(file);
        std::string line;
        while (std::getline(in, line))
        {
            line = Trim(line);
            if (line.empty() || line[0] == '#' || line.starts_with("//")) continue;
            const auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            if (Trim(line.substr(0, eq)) == key) return Trim(line.substr(eq + 1));
        }
        return {};
    }

    std::string Lower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    /*
    Is `needle` (the target exe name, e.g. "FSD-Win64-Shipping.exe") present in this pid's
    command line? /proc/<pid>/comm is truncated to 15 bytes, far short of a real game's exe name,
    so this reads cmdline instead -- NUL-separated argv, and Wine's own process for a Proton game
    carries the exe name in there (as its argv[0] or an early argument) the same way `pgrep -f`
    would find it.
    */
    bool CmdlineContains(int pid, const std::string& needleLower)
    {
        std::ifstream in("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
        if (!in) return false;
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        return Lower(data).find(needleLower) != std::string::npos;
    }

    // First pid whose cmdline matches, or 0. Not cached: a poll-once-a-second scan of /proc is
    // cheap, and caching would just be one more thing to get stale.
    int FindProcess(const std::string& needleLower)
    {
        DIR* d = ::opendir("/proc");
        if (!d) return 0;

        int found = 0;
        while (dirent* e = ::readdir(d))
        {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            const int pid = std::atoi(e->d_name);
            if (pid > 0 && CmdlineContains(pid, needleLower)) { found = pid; break; }
        }
        ::closedir(d);
        return found;
    }

    // Runs `wine bpcrash.exe --once` to completion, inheriting our environment (WINEPREFIX
    // included). This is the only point that ever touches Wine/wineserver.
    int RunOnceInjection(const std::string& wineBin, const std::string& bpcrashExe)
    {
        const pid_t child = ::fork();
        if (child < 0) return -1;
        if (child == 0)
        {
            ::execlp(wineBin.c_str(), wineBin.c_str(), bpcrashExe.c_str(), "--once", nullptr);
            ::_exit(127);   // execlp only returns on failure
        }
        int status = 0;
        ::waitpid(child, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::printf("usage: bpcrash-watch <path-to-wine> <path-to-bpcrash.exe>\n"
                     "       WINEPREFIX must be set in the environment.\n");
        return 1;
    }
    if (!::getenv("WINEPREFIX"))
    {
        std::printf("WINEPREFIX is not set -- export it to the game's compatdata/<appid>/pfx first.\n");
        return 1;
    }

    const std::string wineBin = argv[1];
    const fs::path bpcrashExe = argv[2];
    const std::string target = ReadConfig(bpcrashExe.parent_path() / "bpcrash.cfg", "process");
    if (target.empty())
    {
        std::printf("No target. Put `process = YourGame.exe` in bpcrash.cfg next to bpcrash.exe.\n");
        return 1;
    }
    const std::string needle = Lower(target);

    std::printf("bpcrash-watch -- watching /proc for %s (Ctrl+C to stop) ...\n", target.c_str());

    // Same shape as the Windows loader's own loop: one attempt per pid, reset when it's gone.
    int handled = 0;
    for (;;)
    {
        const int pid = FindProcess(needle);
        if (!pid) handled = 0;
        else if (pid != handled)
        {
            handled = pid;
            std::printf("Found pid %d, running one-shot injection ...\n", pid);
            const int rc = RunOnceInjection(wineBin, bpcrashExe.string());
            std::printf(rc == 0 ? "Done.\n" : "One-shot injection reported a problem (exit %d).\n", rc);
            std::printf("Watching for the next %s ...\n", target.c_str());
        }
        ::usleep(1000 * 1000);
    }
}
