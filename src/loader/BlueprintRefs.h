#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace bpc::blueprint {
namespace fs = std::filesystem;

// Parsed only from the original 'assert  :' line, never from appended analysis.
struct Failure {
    std::string functionName;
    std::string targetClass;  // e.g. PRJ_GrenadeLauncher_C
    std::string callerPackage; // e.g. fsd/content/weaponsntools/grenadelauncher/wpn_grenadelauncher
};

Failure ParseFailure(const std::string& report, const std::string& project);

// A generated class named FOO_C normally comes from FOO.uasset, but is not
// guaranteed to; this function offers candidates, not proven definitions.
std::vector<std::string> ClassPathCandidates(const std::vector<std::string>& pakFiles,
                                               std::string_view className,
                                               std::string_view project);

struct SymbolEvidence {
    bool functionName = false;
    bool className = false;
    bool complete = true; // false: stream incomplete / exceeded conservative scan cap
};

// Bounded ASCII and UTF-16LE literal-name scans; findings only establish name
// presence, not whether a function is implemented, called or imported.
SymbolEvidence SearchBytes(const std::vector<unsigned char>& bytes, const Failure& failure);
SymbolEvidence SearchFile(const fs::path& pak, const Failure& failure,
                          std::uint64_t maxBytes = 512ull * 1024 * 1024);

} // namespace bpc::blueprint
