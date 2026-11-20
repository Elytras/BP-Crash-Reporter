#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bpc::mintfixed {
namespace fs = std::filesystem;

struct Archive {
    fs::path path;
    bool exists = false;
    std::uint64_t byteSize = 0;
    std::optional<std::uint64_t> modifiedUnixMs;
};

struct IndexedPak {
    // Empty member identifies a direct .pak. Otherwise this is the ZIP member
    // name as recorded by mintfixed during installation.
    std::string member;
    std::vector<std::string> packages;
    bool complete = false;
};

struct ArchiveIndex {
    std::string status;
    std::vector<IndexedPak> paks;
};

struct Mod {
    std::string name;
    std::string provider;
    std::string modioReference;
    std::string archiveType;
    std::uint64_t integrationOrder = 0;
    Archive archive;
    ArchiveIndex archiveIndex;
};

struct Context {
    std::uint64_t generatedUnixMs = 0;
    std::uint64_t schemaVersion = 0;
    Archive installedPak;
    std::vector<Mod> installedMods;
};

struct LoadedContext {
    bool present = false;
    bool valid = false;
    bool stale = false; // Installed mods_P.pak no longer matches this snapshot.
    fs::path source;
    std::string error;
    Context context;
};

// Only the game-specific reporter directory is searched. The report itself can be
// copied elsewhere for `--triage` without silently switching to another game's list.
LoadedContext Load(const fs::path& gameExe);

} // namespace bpc::mintfixed
