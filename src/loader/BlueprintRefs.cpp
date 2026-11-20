#include "BlueprintRefs.h"
#include "AnalysisCommon.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string_view>

namespace bpc::blueprint {
namespace {
using shared::Lower;
constexpr std::size_t kMaxReportLines = 100000;
constexpr std::size_t kMaxTokenLength = 128;

std::string NormalizeName(std::string name) {
    // UE-generated Blueprint classes frequently include the _C postfix.
    name = Lower(std::move(name));
    if (name.size() > 2 && name.substr(name.size()-2) == "_c") name.resize(name.size()-2);
    return name;
}
std::string FileStem(std::string_view path) {
    auto slash = path.find_last_of("/\\");
    std::string stem(path.substr(slash == std::string_view::npos ? 0 : slash + 1));
    const auto dot = stem.find_last_of('.');
    if (dot != std::string::npos) stem.resize(dot);
    return Lower(std::move(stem));
}
}

Failure ParseFailure(const std::string& report, const std::string& project) {
    // Match only the original engine exception line, not repeated analysis prose.
    static const std::regex fatal(
        R"(Failed to find function\s+([^\r\n]{1,128}?)\s+in\s+([A-Za-z_][A-Za-z0-9_]{2,127}))",
        std::regex::icase);
    static const std::regex caller(
        R"(^\s*#0\s+(/Game/[A-Za-z0-9_./-]+))", std::regex::icase);
    Failure value;
    std::size_t offset = 0;
    for (std::size_t count = 0; count < kMaxReportLines && offset < report.size(); ++count) {
        const auto end = report.find('\n', offset);
        std::string line = report.substr(offset, (end == std::string::npos ? report.size() : end) - offset);
        offset = end == std::string::npos ? report.size() : end + 1;
        const auto trim = line.find_first_not_of(" \t");
        if (trim == std::string::npos) continue;
        if (line.compare(trim, 6, "assert") == 0 &&
            line.find(':', trim + 6) != std::string::npos &&
            line.find(':', trim + 6) < trim + 12) {
            std::smatch match;
            if (value.functionName.empty() && std::regex_search(line, match, fatal)) {
                value.functionName = match[1];
                value.targetClass = match[2];
            }
        }
        std::smatch match;
        if (value.callerPackage.empty() && std::regex_search(line, match, caller))
            value.callerPackage = shared::PackageKey(match[1], project);
    }
    if (value.functionName.empty() || value.functionName.size() > kMaxTokenLength ||
        value.targetClass.size() > kMaxTokenLength) return {};
    return value;
}

std::vector<std::string> ClassPathCandidates(const std::vector<std::string>& pakFiles,
                                               std::string_view className,
                                               std::string_view project) {
    std::vector<std::string> found;
    if (className.empty()) return found;
    const auto target = NormalizeName(std::string(className));
    for (const auto& entry : pakFiles) {
        const auto lower = Lower(entry);
        const auto ext = lower.find_last_of('.');
        if (ext == std::string::npos ||
            (lower.substr(ext) != ".uasset" && lower.substr(ext) != ".umap")) continue;
        if (FileStem(lower) != target) continue;
        const auto canonical = shared::PackageKey(entry, project);
        if (!canonical.empty() && std::find(found.begin(), found.end(), canonical) == found.end())
            found.push_back(canonical);
        if (found.size() >= 16) break;
    }
    return found;
}

} // namespace bpc::blueprint
