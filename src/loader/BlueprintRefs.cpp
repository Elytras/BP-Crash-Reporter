#include "BlueprintRefs.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <regex>
#include <string_view>

namespace bpc::blueprint {
namespace {
constexpr std::size_t kMaxReportLines = 100000;
constexpr std::size_t kChunk = 1024 * 1024;
constexpr std::size_t kMaxTokenLength = 128;

std::string Lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
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
std::string Canonical(std::string path, std::string_view project) {
    std::replace(path.begin(), path.end(), '\\', '/');
    path = Lower(std::move(path));
    const auto start = path.find("/game/");
    if (start != std::string::npos) path = std::string(project) + "/content/" + path.substr(start + 6);
    else {
        const auto content = path.find(std::string(project) + "/content/");
        if (content == std::string::npos) return {};
        path = path.substr(content);
    }
    const auto slash = path.find_last_of('/');
    const auto dot = path.find('.', slash == std::string::npos ? 0 : slash);
    if (dot != std::string::npos) path.resize(dot);
    return path;
}

// Literal bytes are compared with case folded ASCII. Do not strip punctuation,
// fuzzy-match, or scan arbitrary tiny substrings -- those inflate false positives.
bool WordBoundary(unsigned char c) {
    return !std::isalnum(c) && c != '_';
}
unsigned char Fold(unsigned char c) {
    return static_cast<unsigned char>(std::tolower(c));
}
bool MatchToken(const unsigned char* data, std::size_t len,
                std::string_view token, bool wide) {
    const auto width = wide ? 2u : 1u;
    const auto n = token.size() * width;
    if (!n || len < n) return false;
    for (std::size_t at = 0; at + n <= len; ++at) {
        if (Fold(data[at]) != Fold(static_cast<unsigned char>(token[0]))) continue;
        if (wide && (at+1 >= len || data[at+1])) continue;
        bool ok = true;
        for (std::size_t i = 1; i < token.size(); ++i) {
            if (Fold(data[at+i*width]) != Fold(static_cast<unsigned char>(token[i])) ||
                (wide && data[at+i*width+1] != 0)) { ok = false; break; }
        }
        if (!ok) continue;
        // Anchors rule out matches inside longer identifiers (e.g. PRJ_GrenadeLauncher_C_Old).
        const bool left = at == 0 || (wide ?
             (at < 2 || (data[at-1] == 0 && WordBoundary(data[at-2]))) : WordBoundary(data[at-1]));
        const bool right = at+n == len || (wide ?
             (at+n+1 < len && data[at+n+1] == 0 && WordBoundary(data[at+n])) : WordBoundary(data[at+n]));
        if (left && right) return true;
    }
    return false;
}

struct Scanner {
    Failure failure;
    SymbolEvidence found;
    explicit Scanner(Failure f) : failure(std::move(f)) {}
    void Feed(const unsigned char* bytes, std::size_t size) {
        if (!found.functionName) {
            if (MatchToken(bytes, size, failure.functionName, false) ||
                MatchToken(bytes, size, failure.functionName, true)) found.functionName = true;
            // UE names may use an underscore rather than a space; this is still only a name mention.
            if (!found.functionName && failure.functionName.find(' ') != std::string::npos) {
                std::string alternate = failure.functionName;
                std::replace(alternate.begin(), alternate.end(), ' ', '_');
                found.functionName = MatchToken(bytes, size, alternate, false) ||
                                     MatchToken(bytes, size, alternate, true);
            }
        }
        if (!found.className && !failure.targetClass.empty()) {
            found.className = MatchToken(bytes, size, failure.targetClass, false) ||
                              MatchToken(bytes, size, failure.targetClass, true);
        }
    }
};
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
            value.callerPackage = Canonical(match[1], project);
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
        const auto canonical = Canonical(entry, project);
        if (!canonical.empty() && std::find(found.begin(), found.end(), canonical) == found.end())
            found.push_back(canonical);
        if (found.size() >= 16) break;
    }
    return found;
}

SymbolEvidence SearchBytes(const std::vector<unsigned char>& bytes, const Failure& failure) {
    Scanner scanner(failure);
    if (!bytes.empty()) scanner.Feed(bytes.data(), bytes.size());
    return scanner.found;
}

SymbolEvidence SearchFile(const fs::path& path, const Failure& failure, std::uint64_t maxBytes) {
    Scanner scanner(failure);
    std::ifstream in(path, std::ios::binary);
    if (!in) { scanner.found.complete = false; return scanner.found; }
    std::vector<unsigned char> data(kChunk + 2 * kMaxTokenLength + 4);
    std::size_t carry = 0;
    std::uint64_t scanned = 0;
    const auto overlap = 2 * kMaxTokenLength + 2;
    while (scanned < maxBytes) {
        const auto want = static_cast<std::streamsize>(std::min<std::uint64_t>(kChunk, maxBytes - scanned));
        in.read(reinterpret_cast<char*>(data.data()+carry), want);
        const auto count = in.gcount();
        if (count <= 0) {
            if (!in.eof()) scanner.found.complete = false;
            return scanner.found;
        }
        const auto valid = carry + static_cast<std::size_t>(count);
        scanner.Feed(data.data(), valid);
        scanned += static_cast<std::uint64_t>(count);
        if (scanner.found.functionName && scanner.found.className) return scanner.found;
        carry = std::min(overlap, valid);
        std::copy(data.begin()+valid-carry, data.begin()+valid, data.begin());
    }
    // A capped read means absence of strings is not evidence of absence from the file.
    if (in.peek() != std::char_traits<char>::eof()) scanner.found.complete = false;
    return scanner.found;
}
} // namespace bpc::blueprint
