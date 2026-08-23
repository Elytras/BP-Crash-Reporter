/*
main.cpp

The whole loader: read one line of config, then watch for the target process and inject the DLL
into each one that appears. There is no REPL, no IPC and no command surface, because everything
the tool does happens inside the injected DLL.

It keeps running after the first injection so that restarting the game does not mean restarting
the loader as well. Close the window, or Ctrl+C, when you are done.

	bpcrash.cfg:  process = FSD-Win64-Shipping.exe
*/

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <windows.h>

#include <tlhelp32.h>

#include "resource.h"

namespace fs = std::filesystem;

namespace
{
    /*
    Produces the DLL that actually gets injected, bpcrash_live.dll, beside this exe.

    The payload travels inside this exe as an RCDATA resource, or as a loose bpcrash.dll next to it
    in a build with -DBPC_EMBED_DLL=OFF. Either way we write it out to a separate live copy, since
    LoadLibrary keeps the injected file locked for as long as the game runs and injecting the build
    output directly would make the next compile fail with LNK1104.

    We use LoadLibraryW rather than manual mapping, because that is what makes the DLL a real,
    walkable module and lets the crash handler report its own base and RVAs. It therefore has to
    exist as a file, and it goes beside the exe rather than in %TEMP% so that the crash reports,
    which land next to the DLL, appear where you launched from.
    */
    bool StageLiveDll(const fs::path& src, const fs::path& live)
    {
        std::error_code ec;

        HRSRC res = ::FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_BPDLL), reinterpret_cast<LPCWSTR>(RT_RCDATA));
        if (res)
        {
            const DWORD size = ::SizeofResource(nullptr, res);
            HGLOBAL blob = ::LoadResource(nullptr, res);
            const void* data = blob ? ::LockResource(blob) : nullptr;
            if (data && size)
            {
                // Same size means same build, so leave it alone; a re-run then works while it is loaded.
                if (fs::exists(live) && fs::file_size(live, ec) == size) return true;
                std::ofstream out(live, std::ios::binary | std::ios::trunc);
                if (out) { out.write(static_cast<const char*>(data), size); return true; }
                return fs::exists(live);   // locked, so the existing copy is this same build
            }
        }

        // No embedded payload: stage from the loose DLL beside us.
        if (!fs::exists(src)) return fs::exists(live);
        if (fs::exists(live) && fs::file_size(live, ec) == fs::file_size(src, ec)) return true;
        fs::copy_file(src, live, fs::copy_options::overwrite_existing, ec);
        return !ec || fs::exists(live);
    }

    std::string Trim(std::string s)
    {
        const auto ws = " \t\r\n";
        const auto a = s.find_first_not_of(ws);
        if (a == std::string::npos) return {};
        return s.substr(a, s.find_last_not_of(ws) - a + 1);
    }

    // `key = value`, plus `#` and `//` comments. One key exists, so there is no parser here.
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

    DWORD FindProcess(const std::wstring& name)
    {
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W pe{ sizeof(pe) };
        DWORD pid = 0;
        if (::Process32FirstW(snap, &pe))
        {
            do
            {
                if (::_wcsicmp(pe.szExeFile, name.c_str()) == 0) { pid = pe.th32ProcessID; break; }
            } while (::Process32NextW(snap, &pe));
        }
        ::CloseHandle(snap);
        return pid;
    }

    bool AlreadyInjected(DWORD pid, const std::wstring& dllName)
    {
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;

        MODULEENTRY32W me{ sizeof(me) };
        bool found = false;
        if (::Module32FirstW(snap, &me))
        {
            do
            {
                if (::_wcsicmp(me.szModule, dllName.c_str()) == 0) { found = true; break; }
            } while (::Module32NextW(snap, &me));
        }
        ::CloseHandle(snap);
        return found;
    }

    bool Inject(DWORD pid, const fs::path& dll)
    {
        HANDLE proc = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
        if (!proc) { std::printf("OpenProcess failed (%lu) -- run as administrator?\n", ::GetLastError()); return false; }

        const std::wstring path = dll.wstring();
        const SIZE_T bytes = (path.size() + 1) * sizeof(wchar_t);

        void* remote = ::VirtualAllocEx(proc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        bool ok = false;
        if (remote && ::WriteProcessMemory(proc, remote, path.c_str(), bytes, nullptr))
        {
            auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                ::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
            HANDLE thread = ::CreateRemoteThread(proc, nullptr, 0, loadLib, remote, 0, nullptr);
            if (thread)
            {
                ::WaitForSingleObject(thread, 30000);
                DWORD result = 0;
                ::GetExitCodeThread(thread, &result);
                ok = result != 0;   // LoadLibraryW's HMODULE, truncated; nonzero means it mapped
                ::CloseHandle(thread);
            }
        }
        if (remote) ::VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        ::CloseHandle(proc);
        return ok;
    }
}

int wmain(int argc, wchar_t** argv)
{
    wchar_t self[MAX_PATH]{};
    ::GetModuleFileNameW(nullptr, self, MAX_PATH);
    const fs::path dir = fs::path(self).parent_path();
    const fs::path dll = dir / L"bpcrash.dll";        // the build output / shipped payload
    const fs::path live = dir / L"bpcrash_live.dll";  // the copy that actually gets injected

    // argv[1] overrides the config file, for the one-off case.
    std::string target = (argc > 1) ? fs::path(argv[1]).string() : ReadConfig(dir / "bpcrash.cfg", "process");
    if (target.empty())
    {
        std::printf("No target. Put `process = YourGame.exe` in bpcrash.cfg, or pass it as an argument.\n");
        return 1;
    }
    if (!StageLiveDll(dll, live))
    {
        std::printf("Could not place %ls next to the loader.\n", live.c_str());
        return 1;
    }

    const std::wstring wtarget = fs::path(target).wstring();
    std::printf("BPCrashHandler -- watching for %s (Ctrl+C to stop) ...\n", target.c_str());

    /*
    We stay alive and keep polling rather than exiting after the first injection, so that
    restarting the game picks the tool back up without restarting the loader too. `handled` is the
    pid we last acted on: a process only gets one attempt, whether it succeeded, failed, or was
    already injected, and a new pid is what triggers the next one. Retrying the same pid in a loop
    would only spin on a permissions or antivirus problem that another second will not fix.
    */
    DWORD handled = 0;
    for (;;)
    {
        const DWORD pid = FindProcess(wtarget);
        if (!pid) handled = 0;   // gone; the next launch is a fresh target even if Windows reuses the pid
        else if (pid != handled)
        {
            handled = pid;
            if (AlreadyInjected(pid, L"bpcrash_live.dll"))
            {
                std::printf("Already loaded in pid %lu.\n", pid);
            }
            else
            {
                std::printf("Found pid %lu, injecting ...\n", pid);
                std::printf(Inject(pid, live)
                    ? "Injected. Reports will be written next to the DLL.\n"
                    : "Injection failed. Waiting for the next launch.\n");
            }
            std::printf("Watching for the next %s ...\n", target.c_str());
        }
        ::Sleep(1000);
    }
}
