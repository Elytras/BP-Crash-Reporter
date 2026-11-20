#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace bpc::mintfixed {
namespace fs = std::filesystem;

struct Archive {
    fs::path path;
    bool exists = false;
    std::uint64_t byteSize = 0;
};

struct Mod {
    std::string name;
    std::string provider;
    std::string modioReference;
    std::string sha256; // Recorded by mintfixed; not independently checked by this scanner.
    std::string archiveType;
    std::uint64_t integrationOrder = 0;
    Archive archive;
    bool nestedPaksMustBeScanned = false;
};

struct Context {
    std::uint64_t generatedUnixMs = 0;
    Archive installedPak;
    std::vector<Mod> installedMods;
};

struct LoadedContext {
    bool present = false;
    bool valid = false;
    fs::path source;
    std::string error;
    Context context;
};

// Only the game-specific reporter directory is searched. The report itself can be
// copied elsewhere for `--triage` without silently switching to another game's list.
LoadedContext Load(const fs::path& gameExe);

struct ZipStats {
    std::size_t pakEntries = 0;
    std::size_t decoded = 0;
    std::size_t skipped = 0;
    std::string warning;
};

// Lists PAKs within ZIP archives, including extensionless mintfixed cache blobs.
// Inflates one member at a time, in memory, with strict size/count limits.
ZipStats VisitZipPaks(const fs::path& archive,
    const std::function<void(const std::string&, const std::vector<unsigned char>&)>& visitor);

} // namespace bpc::mintfixed
