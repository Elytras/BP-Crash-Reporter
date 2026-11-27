#include "MintfixedContext.h"
#include "FileModifiedUnixMs.h"
#include "AnalysisCommon.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bpc::mintfixed {
namespace {
using Json = nlohmann::json;
constexpr std::size_t kMaxJsonBytes = 64 * 1024 * 1024;
constexpr std::size_t kMaxMods = 4096;
constexpr std::size_t kMaxPackagesPerPak = 65536;
constexpr std::size_t kMaxPaksPerMod = 64;
constexpr std::size_t kMaxTotalPackages = 300000;
constexpr unsigned kMaxDepth = 24;
constexpr std::size_t kMaxObjectFields = 128;

// Keep the constraints of the former parser, but delegate JSON lexing,
// Unicode escapes, string decoding, and number parsing to nlohmann/json.
// A callback is needed because the library normally accepts duplicate keys.
Json ParseManifest(const std::string& body) {
    if (body.size() > kMaxJsonBytes || body.find('\0') != std::string::npos)
        throw std::runtime_error("invalid manifest size or raw NUL byte");

    std::vector<std::set<std::string>> objectKeys;
    auto callback = [&objectKeys](int depth, Json::parse_event_t event, Json& parsed) {
        if (depth < 0 || depth > static_cast<int>(kMaxDepth))
            throw std::runtime_error("manifest nesting depth exceeds limit");
        switch (event) {
        case Json::parse_event_t::object_start:
            objectKeys.emplace_back();
            break;
        case Json::parse_event_t::key: {
            if (objectKeys.empty()) throw std::runtime_error("unexpected JSON key");
            auto& seen = objectKeys.back();
            if (!seen.insert(parsed.get<std::string>()).second)
                throw std::runtime_error("duplicate JSON object key");
            if (seen.size() > kMaxObjectFields)
                throw std::runtime_error("too many JSON object fields");
            break;
        }
        case Json::parse_event_t::object_end:
            if (objectKeys.empty()) throw std::runtime_error("unexpected JSON object end");
            objectKeys.pop_back();
            break;
        default:
            break;
        }
        return true; // never discard fields: schema checks must see the complete document
    };
    Json json = Json::parse(body, callback, true, false /* ignore_comments */);
    if (!objectKeys.empty()) throw std::runtime_error("incomplete JSON object");
    return json;
}

// Preserve limits even for fields the schema does not currently interpret.
// This prevents oversized unknown arrays and non-integer JSON numbers from
// bypassing the checks that the original strict parser enforced.
void ValidateTree(const Json& value, unsigned depth = 0) {
    if (depth > kMaxDepth) throw std::runtime_error("manifest nesting depth exceeds limit");
    if (value.is_object()) {
        if (value.size() > kMaxObjectFields) throw std::runtime_error("too many JSON object fields");
        for (const auto& it : value.items()) ValidateTree(it.value(), depth + 1);
    } else if (value.is_array()) {
        if (value.size() > kMaxPackagesPerPak + 1)
            throw std::runtime_error("oversized JSON array");
        for (const auto& element : value) ValidateTree(element, depth + 1);
    } else if (value.is_number()) {
        if (!value.is_number_unsigned() &&
            (!value.is_number_integer() || value.get<Json::number_integer_t>() < 0))
            throw std::runtime_error("invalid JSON number");
    }
}

const Json& Field(const Json& object, std::string_view key) {
    if (!object.is_object()) throw std::runtime_error("expected JSON object");
    const auto it = object.find(std::string(key));
    if (it == object.end())
        throw std::runtime_error("missing field: " + std::string(key));
    return *it;
}

std::string StringField(const Json& object, std::string_view key) {
    const auto& value = Field(object, key);
    if (!value.is_string()) throw std::runtime_error("invalid string field: " + std::string(key));
    return value.get<std::string>();
}

std::string OptionalString(const Json& object, std::string_view key) {
    if (!object.is_object()) throw std::runtime_error("expected JSON object");
    const auto it = object.find(std::string(key));
    return it != object.end() && it->is_string() ? it->get<std::string>() : "";
}

bool BoolField(const Json& object, std::string_view key) {
    const auto& value = Field(object, key);
    if (!value.is_boolean()) throw std::runtime_error("invalid boolean field: " + std::string(key));
    return value.get<bool>();
}

std::uint64_t UnsignedValue(const Json& value, std::string_view key) {
    if (value.is_number_unsigned()) return value.get<std::uint64_t>();
    if (value.is_number_integer()) {
        const auto n = value.get<Json::number_integer_t>();
        if (n >= 0) return static_cast<std::uint64_t>(n);
    }
    throw std::runtime_error("invalid unsigned integer field: " + std::string(key));
}

std::uint64_t UnsignedField(const Json& object, std::string_view key) {
    return UnsignedValue(Field(object, key), key);
}

const Json& ContainerField(const Json& object, std::string_view key, bool array) {
    const auto& value = Field(object, key);
    if (array ? !value.is_array() : !value.is_object())
        throw std::runtime_error("invalid container field: " + std::string(key));
    return value;
}

Archive ParseArchive(const Json& value) {
    Archive archive;
    const auto path = StringField(value, "path");
    if (path.empty() || path.find('\0') != std::string::npos)
        throw std::runtime_error("invalid archive path");
    archive.path = fs::u8path(path);
    // Accept the optional portable locator only for a POSIX absolute path
    // naming the fixed merged PAK. Never resolve an arbitrary manifest path.
    const auto relative = value.find("relative_path");
    constexpr std::string_view suffix = "/Content/Paks/mods_P.pak";
    if (relative != value.end() && relative->is_string() &&
        relative->get<std::string>() == "Content/Paks/mods_P.pak" &&
        path.size() >= suffix.size() && path.front() == '/' &&
        (path.size() < 2 || path[1] != '/') &&
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0) {
        archive.portableInstalledPak = true;
    }
    archive.exists = BoolField(value, "exists");
    const auto& byteSize = Field(value, "byte_size");
    if (byteSize.is_null()) {
        if (archive.exists) throw std::runtime_error("existing archive has null byte_size");
    } else {
        archive.byteSize = UnsignedValue(byteSize, "byte_size");
    }
    const auto& modified = Field(value, "modified_unix_ms");
    if (!modified.is_null()) archive.modifiedUnixMs = UnsignedValue(modified, "modified_unix_ms");
    return archive;
}

ArchiveIndex ParseIndex(const Json& value, std::size_t& totalPackages) {
    ArchiveIndex index;
    index.status = StringField(value, "status");
    if (index.status != "complete" && index.status != "partial" && index.status != "unreadable")
        throw std::runtime_error("invalid archive index status");
    const auto& paks = ContainerField(value, "paks", true);
    if (paks.size() > kMaxPaksPerMod) throw std::runtime_error("too many indexed PAK members");
    for (const auto& entry : paks) {
        if (!entry.is_object()) throw std::runtime_error("invalid indexed PAK entry");
        IndexedPak pak;
        const auto& member = Field(entry, "member");
        if (!member.is_null() && !member.is_string())
            throw std::runtime_error("invalid ZIP member name");
        if (member.is_string()) pak.member = member.get<std::string>();
        if (pak.member.size() > 1024 || pak.member.find('\0') != std::string::npos)
            throw std::runtime_error("invalid ZIP member length");
        pak.complete = BoolField(entry, "complete");
        const auto& packages = ContainerField(entry, "packages", true);
        if (packages.size() > kMaxPackagesPerPak || packages.size() > kMaxTotalPackages - totalPackages)
            throw std::runtime_error("indexed package count exceeds limit");
        totalPackages += packages.size();
        for (const auto& package : packages) {
            if (!package.is_string()) throw std::runtime_error("invalid indexed package name");
            const auto name = package.get<std::string>();
            if (name.empty() || name.size() > 1024 || name.find('\0') != std::string::npos)
                throw std::runtime_error("invalid indexed package name");
            pak.packages.push_back(name);
        }
        if (pak.complete && pak.packages.empty())
            throw std::runtime_error("complete PAK must contain indexed packages");
        index.paks.push_back(std::move(pak));
    }
    if (index.status == "complete" && (index.paks.empty() ||
        std::any_of(index.paks.begin(), index.paks.end(),
                    [](const IndexedPak& pak) { return !pak.complete; })))
        throw std::runtime_error("inconsistent complete archive index");
    return index;
}
// Compare to the actual merged PAK, never an arbitrary file named by JSON.
// Check both size and mtime; this does not cryptographically bind a snapshot to
// the crash, but blocks attribution after an install/uninstall/profile change.
bool MatchesInstalledPak(const Archive& recorded, const fs::path& gameExe) {
    const auto project = shared::ProjectDir(gameExe);
    if (project.empty() || !recorded.exists || !recorded.modifiedUnixMs) return false;
    const auto expected = project / "Content" / "Paks" / "mods_P.pak";
    std::error_code ec;
    if (!recorded.portableInstalledPak &&
        (!fs::equivalent(expected, recorded.path, ec) || ec)) return false;
    // Portable snapshots still validate the actual game-relative merged PAK,
    // never a caller-selected path. Size and millisecond mtime remain strict.
    ec.clear();
    const auto size = fs::file_size(expected, ec);
    if (ec || size != recorded.byteSize) return false;
    const auto milliseconds = FileModifiedUnixMs(expected);
    return milliseconds && *milliseconds == *recorded.modifiedUnixMs;
}
} // namespace

LoadedContext Load(const fs::path& gameExe) {
    LoadedContext result;
    // Do not trust an arbitrary bpcrash.cfg to select another user's context.
    if (shared::ProjectDir(gameExe).empty()) return result;
    result.source = gameExe.parent_path() / "mintfixed-bpcrash" / "crash_context.json";
    std::error_code ec;
    if (!fs::is_regular_file(result.source, ec)) return result;
    result.present = true;
    const auto size = fs::file_size(result.source, ec);
    if (ec || size > kMaxJsonBytes) { result.error = "context exceeds 64 MiB or cannot be read"; return result; }
    try {
        std::ifstream in(result.source, std::ios::binary);
        if (!in) throw std::runtime_error("cannot read manifest");
        std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        auto json = ParseManifest(body);
        ValidateTree(json);
        if (!json.is_object() || UnsignedField(json, "schema_version") != 2 ||
            StringField(json, "producer") != "mintfixed" ||
            !BoolField(json, "captured_after_successful_install"))
            throw std::runtime_error("unsupported or incomplete mintfixed context schema");
        result.context.schemaVersion = 2;
        result.context.generatedUnixMs = UnsignedField(json, "generated_unix_ms");
        result.context.installedPak = ParseArchive(ContainerField(json, "installed_pak", false));
        const auto& mods = ContainerField(json, "installed_mods", true);
        if (mods.size() > kMaxMods) throw std::runtime_error("too many installed mods");
        std::set<std::uint64_t> seenOrder;
        std::size_t totalPackages = 0;
        for (const auto& modValue : mods) {
            if (!modValue.is_object()) throw std::runtime_error("invalid mod entry");
            Mod mod;
            mod.name = StringField(modValue, "name");
            if (mod.name.empty()) throw std::runtime_error("empty mod name");
            mod.provider = StringField(modValue, "provider");
            mod.integrationOrder = UnsignedField(modValue, "integration_order");
            if (!seenOrder.insert(mod.integrationOrder).second) throw std::runtime_error("duplicate integration order");
            mod.archive = ParseArchive(ContainerField(modValue, "archive", false));
            mod.archiveType = StringField(modValue, "archive_type");
            mod.modioReference = OptionalString(modValue, "modio_reference");
            mod.archiveIndex = ParseIndex(ContainerField(modValue, "archive_index", false), totalPackages);
            result.context.installedMods.push_back(std::move(mod));
        }
        std::sort(result.context.installedMods.begin(), result.context.installedMods.end(),
                  [](const Mod& a, const Mod& b) { return a.integrationOrder < b.integrationOrder; });
        if (!MatchesInstalledPak(result.context.installedPak, gameExe)) {
            result.stale = true;
            result.error = "installed mods_P.pak is missing, replaced or differs in size/modified_unix_ms";
            return result;
        }
        result.valid = true;
    } catch (const std::exception& e) { result.error = e.what(); }
    return result;
}

} // namespace bpc::mintfixed
