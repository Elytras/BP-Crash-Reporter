#pragma once

// Shared post-exit report selection. No Win32 or Wine dependencies.
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <system_error>

namespace bpc::reports
{
    namespace fs = std::filesystem;

    // Only accept the filename format emitted by Dump.cpp. The PID is the
    // Windows process ID, including when the game is running under Wine.
    inline std::optional<std::uint64_t> Sequence(std::string_view name, std::string_view pid)
    {
        static const std::regex pattern(R"(^bpcrash_[0-9]{8}_[0-9]{6}_([0-9]+)_([0-9]+)_t[0-9]+\.txt$)");
        std::match_results<std::string_view::const_iterator> match;
        if (!std::regex_match(name.begin(), name.end(), match, pattern) || match[1].str() != pid)
            return std::nullopt;
        const auto seq = match[2].str();
        std::uint64_t value = 0;
        const auto [end, error] = std::from_chars(seq.data(), seq.data() + seq.size(), value);
        if (error != std::errc{} || end != seq.data() + seq.size()) return std::nullopt;
        return value;
    }

    // Prefer the latest first-chance report carrying a UE assertion, otherwise
    // the latest first-chance report. A session cutoff is optional on Windows.
    // Use a deterministic filename tie-breaker if two files share a sequence.
    inline fs::path Select(const fs::path& dir, std::string_view pid,
                           std::optional<fs::file_time_type> since, std::error_code& ec)
    {
        fs::path picked;
        std::string bestName;
        std::uint64_t bestSeq = 0;
        bool bestFatal = false;
        ec.clear();
        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
        {
            const auto& entry = *it;
            const auto utf8 = entry.path().filename().u8string();
            const std::string name(utf8.begin(), utf8.end());
            const auto seq = Sequence(name, pid);
            if (!seq) continue;
            std::error_code fileError;
            if (!fs::is_regular_file(entry.symlink_status(fileError)) || fileError) continue;
            if (since)
            {
                const auto stamp = entry.last_write_time(fileError);
                if (fileError || stamp < *since) continue;
            }
            std::ifstream report(entry.path());
            std::string line;
            if (!std::getline(report, line) || !std::getline(report, line) ||
                !line.starts_with("reason  : first-chance")) continue;
            bool fatal = false;
            while (std::getline(report, line))
            {
                if (line.starts_with("assert  : ")) { fatal = true; break; }
            }
            if (picked.empty() || (fatal && !bestFatal) ||
                (fatal == bestFatal && (*seq > bestSeq || (*seq == bestSeq && name > bestName))))
            {
                picked = entry.path();
                bestName = name;
                bestSeq = *seq;
                bestFatal = fatal;
            }
        }
        return ec ? fs::path{} : picked;
    }
}
