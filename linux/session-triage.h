#pragma once
// Native, finite post-exit mode. The caller waits for the original game
// command; the session record provides Wine PID and Windows paths.
#include "../src/loader/ReportSelection.h"

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>

namespace bpc_session
{
    namespace fs = std::filesystem;

    inline bool WindowsAbsolute(std::string_view path)
    {
        if (path.find('\0') != std::string_view::npos || path.find('\r') != std::string_view::npos)
            return false;
        // Wine drive mappings are explicit. Never guess a Windows path from
        // the Linux mount point or append a mod-manager-specific directory.
        return path.size() >= 3 &&
            ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
            path[1] == ':' && (path[2] == '\\' || path[2] == '/');
    }

    inline int Run(int argc, char** argv)
    {
        if (argc < 5)
        {
            std::fprintf(stderr, "usage: bpcrash-watch --triage-only <session-file> <triage-exe> <Proton command...>\n");
            return 2;
        }
        const fs::path session = argv[2];
        const fs::path reporter = argv[3];
        std::ifstream in(session);
        std::string pid, game, windowsDir;
        if (!std::getline(in, pid) || !std::getline(in, game) || !std::getline(in, windowsDir))
        {
            std::fprintf(stderr, "Invalid session record: expected PID, Windows game path and Windows report directory\n");
            return 1;
        }
        for (auto* line : {&pid, &game, &windowsDir})
            if (!line->empty() && line->back() == '\r') line->pop_back();
        if (pid.empty() || pid.size() > 10 || pid.find_first_not_of("0123456789") != std::string::npos ||
            !WindowsAbsolute(game) || !WindowsAbsolute(windowsDir))
        {
            std::fprintf(stderr, "Invalid PID or Windows path in session record\n");
            return 1;
        }
        if (windowsDir.back() != '\\' && windowsDir.back() != '/') windowsDir += '\\';
        std::error_code ec;
        const auto since = fs::last_write_time(session, ec);
        if (ec) return 1;
        const auto nativeDir = session.has_parent_path() ? session.parent_path() : fs::path(".");
        const auto picked = bpc::reports::Select(nativeDir, pid, since, ec);
        if (ec)
        {
            std::fprintf(stderr, "Could not scan report directory: %s\n", ec.message().c_str());
            return 1;
        }
        if (picked.empty())
        {
            std::printf("No first-chance report for Wine PID %s in this session.\n", pid.c_str());
            return 0;
        }
        std::vector<std::string> args;
        for (int i = 4; i < argc; ++i) args.emplace_back(argv[i]);
        args.push_back(reporter.string());
        args.emplace_back("--triage");
        args.push_back(windowsDir + picked.filename().string());
        args.push_back(game);
        std::vector<char*> childArgs;
        for (auto& arg : args) childArgs.push_back(arg.data());
        childArgs.push_back(nullptr);
        std::printf("Running post-exit triage for %s\n", picked.filename().c_str());
        std::fflush(stdout);
        const pid_t child = ::fork();
        if (child < 0) return 1;
        if (child == 0)
        {
            ::execvp(childArgs[0], childArgs.data());
            ::_exit(127);
        }
        // The caller owns the process lifetime and must enforce a timeout.
        int status = 0;
        pid_t waited;
        do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
} // namespace bpc_session
