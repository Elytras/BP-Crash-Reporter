#pragma once
// Read-only post-exit triage helpers, used by the original loader and optional mintfixed analysis.
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace bpc::shared {
namespace fs = std::filesystem;
inline std::string Lower(std::string value) {
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
inline bool StartsWith(std::string_view value, std::string_view prefix) { return value.starts_with(prefix); }
inline std::string PathUtf8(const fs::path& path) {
    const auto text = path.u8string();
    return std::string(text.begin(), text.end());
}
inline fs::path ProjectDir(const fs::path& exe) {
    const auto bin = exe.parent_path().parent_path();
    return Lower(PathUtf8(bin.filename())) == "binaries" ? bin.parent_path() : fs::path{};
}
inline std::string ProjectName(const fs::path& exe) {
    const auto dir = ProjectDir(exe);
    return dir.empty() ? std::string{} : Lower(PathUtf8(dir.filename()));
}
inline fs::path VanillaPakPath(const fs::path& exe) {
    const auto projectDir = ProjectDir(exe);
    if (projectDir.empty()) return {};
    fs::path name = projectDir.filename();
    name += "-WindowsNoEditor.pak";
    return projectDir / "Content" / "Paks" / name;
}
inline std::vector<std::string> ReadLines(const fs::path& file) {
    std::ifstream in(file, std::ios::binary);
    std::vector<std::string> lines;
    for (std::string line; std::getline(in, line); ) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(std::move(line));
    }
    return lines;
}
inline std::vector<char> ReadAt(std::istream& in, std::int64_t offset, std::int64_t size) {
    if (offset < 0 || size <= 0 || size > (std::int64_t{1} << 30)) return {};
    in.clear();
    in.seekg(0, std::ios::end);
    const auto end = static_cast<std::streamoff>(in.tellg());
    if (end < 0 || offset > end || size > end - offset) return {};
    std::vector<char> data(static_cast<std::size_t>(size));
    in.seekg(offset);
    in.read(data.data(), static_cast<std::streamsize>(size));
    return in ? data : std::vector<char>{};
}
// Consistent comparison key for indexed PAK names and UE object/package paths.
// Runtime instance suffixes (e.g. .Foo_C:Function) are not package names.
inline std::string PackageKey(std::string value, std::string_view project) {
    std::replace(value.begin(), value.end(), '\\', '/');
    value = Lower(std::move(value));
    const auto delimiter = value.find_first_of(" \r\n\t\"'<>|,;(){}[]");
    if (delimiter != std::string::npos) value.resize(delimiter);
    const auto proj = Lower(std::string(project));
    // UE object paths begin with /Game/ or /Engine/. Do NOT search for those
    // substrings inside mounted PAK filenames: Maps/Game/ and Maps/Engine/
    // are legitimate directories, not virtual roots.
    if (value.starts_with("/game/")) value = proj + "/content/" + value.substr(6);
    else if (value.starts_with("/engine/")) value = "engine/content/" + value.substr(8);
    else {
        // A PAK index may include ../../../ and other mount-prefix components.
        // Recognize the project content root only on a full path boundary.
        const auto findRoot = [&](const std::string& prefix) {
            auto pos = value.find(prefix);
            while (pos != std::string::npos && pos > 0 && value[pos - 1] != '/')
                pos = value.find(prefix, pos + 1);
            return pos;
        };
        const auto gameRoot = findRoot(proj + "/content/");
        const auto engineRoot = findRoot("engine/content/");
        std::size_t pos = std::string::npos;
        if (gameRoot != std::string::npos && engineRoot != std::string::npos)
            pos = (std::min)(gameRoot, engineRoot);
        else if (gameRoot != std::string::npos) pos = gameRoot;
        else pos = engineRoot;
        if (pos == std::string::npos) return {};
        value.erase(0, pos);
    }
    const auto slash = value.find_last_of('/');
    const auto dot = value.find('.', slash == std::string::npos ? 0 : slash);
    if (dot != std::string::npos) value.resize(dot);
    while (!value.empty() && (value.back() == '/' || value.back() == ':')) value.pop_back();
    return value;
}
} // namespace bpc::shared
