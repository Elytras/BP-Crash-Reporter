#include "AssetAnalysis.h"
#include "Triage.h"
#include "MintfixedContext.h"
#include "BlueprintRefs.h"
#include "AnalysisCommon.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <cstdint>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace bpc::analysis {
namespace {
using shared::Lower;
using shared::PathUtf8;
using shared::ProjectName;
constexpr std::string_view kMintfixedMarker = "--- mintfixed mod attribution (bpcrash.exe) ---";
constexpr size_t kMaxReportBytes = 16 * 1024 * 1024;
constexpr size_t kMaxPaths = 48;

struct Candidate {
    std::string display;
    std::set<std::string> reasons;
    int weight = 0;
};

// Runtime object owners are not cooked packages. In particular, UE reports
// spawned objects as /Game/Maps/<level>.<level>.PersistentLevel:<actor>.
// Treating that outer map as the failing Blueprint hides the real class.
bool RuntimeInstancePath(std::string_view path) {
    const auto lower = Lower(std::string(path));
    if (lower.find(".persistentlevel") != std::string::npos ||
        lower.find(":persistentlevel") != std::string::npos) return true;
    // Some messages omit PersistentLevel and give only a numbered, spawned
    // Blueprint object after the package separator. A function named :Foo
    // isn't a runtime owner, but :HUD_Foo_C_2147463093 is.
    const auto colon = lower.find(':');
    if (colon == std::string::npos) return false;
    const auto suffix = lower.substr(colon + 1);
    const auto generated = suffix.rfind("_c_");
    if (generated == std::string::npos) return false;
    const auto firstDigit = generated + 3;
    return firstDigit < suffix.size() &&
           std::isdigit(static_cast<unsigned char>(suffix[firstDigit])) &&
           std::all_of(suffix.begin() + firstDigit, suffix.end(), [](unsigned char c) {
               return std::isdigit(c);
           });
}

std::map<std::string, Candidate> FindCandidates(const std::string& report, const std::string& project) {
    std::map<std::string, Candidate> found;
    const std::regex gamePath(R"((/(?:Game|Engine)/[A-Za-z0-9_./:\-]+))", std::regex::icase);
    const std::regex contentPath(R"((([A-Za-z0-9_]+[/\\]Content[/\\][A-Za-z0-9_./\\\-]+\.(?:uasset|uexp|umap))))", std::regex::icase);
    static constexpr std::string_view loadMarker =
        "--- load triage (written by bpcrash.exe after the game exited) ---";

    // SuperStruct dependency exports are useful only when the triage matched
    // the fatal to the relevant last dependency dump. A "context only" dump
    // must not become source-attribution evidence.
    bool trustedLoadContext = false;
    if (const auto start = report.find(loadMarker); start != std::string::npos) {
        auto end = report.find("\n--- ", start + loadMarker.size());
        if (end == std::string::npos) end = report.size();
        const std::string_view section(report.data() + start, end - start);
        trustedLoadContext = section.find("\nverdict : ") != std::string_view::npos;
    }

    std::istringstream input(report);
    std::string line;
    std::size_t count = 0;
    bool inLoadTriage = false;
    while (std::getline(input, line) && count++ < 150000) {
        if (line.starts_with(loadMarker)) { inLoadTriage = true; continue; }
        // Do not re-parse our own output (or a prior version of it).
        if (line.starts_with("--- asset overlap") ||
            line.starts_with("--- mintfixed mod attribution") ||
            line.starts_with("--- blueprint function compatibility")) break;
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        const auto label = std::string_view(line).substr(first);
        const bool isFrame = !inLoadTriage && label.size() > 2 && label[0] == '#' &&
                             std::isdigit(static_cast<unsigned char>(label[1]));
        const bool isFatal = !inLoadTriage && label.starts_with("assert  : ");
        const bool isLoad = inLoadTriage && trustedLoadContext &&
                            (label.starts_with("creating:") || label.starts_with("missing :") ||
                             label.starts_with("in file :"));
        if (!isFrame && !isFatal && !isLoad) continue;
        const int weight = isFrame ? 2 : 3;
        auto add = [&](const std::string& original) {
            if (RuntimeInstancePath(original)) return;
            const std::string canonical = shared::PackageKey(original, project);
            if (canonical.empty() || canonical == "engine/content/transient") return;
            if (!found.contains(canonical) && found.size() >= kMaxPaths) return;
            auto& record = found[canonical];
            if (record.display.empty()) record.display = original;
            record.weight = std::max(record.weight, weight);
            record.reasons.insert(isLoad ? "validated SuperStruct dependency" :
                                  (isFatal ? "fatal/load context" : "Blueprint stack frame"));
        };
        for (auto it = std::sregex_iterator(line.begin(), line.end(), gamePath);
             it != std::sregex_iterator(); ++it) add((*it)[1]);
        for (auto it = std::sregex_iterator(line.begin(), line.end(), contentPath);
             it != std::sregex_iterator(); ++it) add((*it)[1]);
    }
    return found;
}

std::string SafeText(std::string value, std::size_t limit = 256) {
    if (value.size() > limit) value.resize(limit);
    for (char& c : value) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
    return value;
}

struct ModHit {
    const mintfixed::Mod* mod = nullptr;
    std::string member;
};

// This is an evidence-based source-archive match, NOT a determination of what
// ultimately loaded in memory or what made the engine crash.
std::string AnalyzeMintfixed(const mintfixed::LoadedContext& loaded,
                             const std::string& report, const fs::path& gameExe) {
    std::ostringstream out;
    out << "\n" << kMintfixedMarker << "\n";
    if (!loaded.valid) {
        out << (loaded.stale ? "status                  : stale_context\n"
                             : "status                  : invalid_context\n");
        out << "context.error           : " << SafeText(loaded.error) << "\n";
        return out.str();
    }
    const auto& context = loaded.context;
    const auto project = ProjectName(gameExe);
    if (project.empty()) {
        out << "status                  : invalid_game_executable_layout\n";
        return out.str();
    }
    const auto candidates = FindCandidates(report, project);
    const auto failure = blueprint::ParseFailure(report, project);
    const bool missingFunction = !failure.functionName.empty();
    out << "context.path              : " << SafeText(PathUtf8(loaded.source), 1024) << "\n";
    out << "context.generated_unix_ms : " << context.generatedUnixMs << "\n";
    out << "context.schema_version   : " << context.schemaVersion << "\n";
    out << "context.installed_mods    : " << context.installedMods.size() << "\n";
    if (candidates.empty() && !missingFunction) {
        out << "scan.assets.detected      : 0\n";
        out << "status                    : no_recognized_assets_or_missing_functions\n";
        return out.str();
    }

    struct BlueprintModEvidence {
        const mintfixed::Mod* mod = nullptr;
        // Map each class package to its originating PAK members. A class
        // candidate alone is not enough to identify the source ZIP member.
        // Empty member denotes a direct PAK, not a ZIP entry.
        std::map<std::string, std::set<std::string>> classPackages;
        bool ownsCallerPackage = false;
    };
    std::map<std::uint64_t, BlueprintModEvidence> blueprintHits;
    std::map<std::string, std::string> vanillaClassCandidates;
    std::map<std::string, std::vector<ModHit>> found;
    std::size_t indexed = 0, incomplete = 0, nestedPaks = 0, packageEntries = 0;
    for (const auto& mod : context.installedMods) {
        // The v2 manifest was generated after the successful mintfixed install.
        // No source archives are opened by the reporter during post-crash triage.
        if (mod.archiveIndex.status == "complete") ++indexed;
        else ++incomplete;
        for (const auto& pak : mod.archiveIndex.paks) {
            if (!pak.member.empty()) ++nestedPaks;
            packageEntries += pak.packages.size();
            std::set<std::string> matches;
            for (const auto& file : pak.packages) {
                const auto key = shared::PackageKey(file, project);
                if (candidates.contains(key)) matches.insert(key);
                if (missingFunction && !failure.callerPackage.empty() && key == failure.callerPackage) {
                    auto& evidence = blueprintHits[mod.integrationOrder];
                    evidence.mod = &mod;
                    evidence.ownsCallerPackage = true;
                }
            }
            for (const auto& key : matches) found[key].push_back(ModHit{&mod, pak.member});
            if (missingFunction) {
                const auto classes = blueprint::ClassPathCandidates(pak.packages, failure.targetClass, project);
                if (!classes.empty()) {
                    auto& evidence = blueprintHits[mod.integrationOrder];
                    evidence.mod = &mod;
                    for (const auto& classPackage : classes)
                        evidence.classPackages[classPackage].insert(pak.member);
                }
            }
        }
    }
    if (missingFunction) {
        // FName generated class names usually map to an identically named .uasset.
        // Search the vanilla PAK index by filename, not the runtime /Engine/Transient path.
        const auto vanilla = shared::VanillaPakPath(gameExe);
        std::error_code vanillaError;
        if (fs::is_regular_file(vanilla, vanillaError)) {
            for (const auto& key : blueprint::ClassPathCandidates(
                     triage::PakFiles(vanilla), failure.targetClass, project))
                vanillaClassCandidates.emplace(key, PathUtf8(vanilla));
        }
    }
    out << "scan.source                   : mintfixed_manifest_v2\n";
    out << "scan.archives.indexed         : " << indexed << "\n";
    out << "scan.archives.incomplete      : " << incomplete << "\n";
    out << "scan.nested_zip_paks          : " << nestedPaks << "\n";
    out << "scan.package_entries          : " << packageEntries << "\n";
    std::vector<std::pair<std::string, Candidate>> ordered(candidates.begin(), candidates.end());
    std::stable_sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        return a.second.weight > b.second.weight;
    });
    struct RankedMod { const mintfixed::Mod* mod; int score = 0; std::size_t assets = 0; };
    std::map<std::uint64_t, RankedMod> ranking;
    for (const auto& [key, candidate] : ordered) {
        const auto hit = found.find(key);
        if (hit == found.end()) continue;
        std::set<std::uint64_t> counted;
        for (const auto& source : hit->second) {
            if (!counted.insert(source.mod->integrationOrder).second) continue;
            auto& score = ranking[source.mod->integrationOrder];
            score.mod = source.mod;
            score.score += candidate.weight;
            ++score.assets;
        }
    }
    std::vector<RankedMod> ranked;
    for (const auto& [order, score] : ranking) ranked.push_back(score);
    std::stable_sort(ranked.begin(), ranked.end(), [](const RankedMod& a, const RankedMod& b) {
        if (a.score != b.score) return a.score > b.score;
        return a.mod->integrationOrder < b.mod->integrationOrder;
    });
    out << "ranked_mods.total         : " << ranked.size() << "\n";
    if (!ranked.empty()) {
        out << "ranked_mods.score_weights : fatal=3, blueprint_frame=2\n";
        for (std::size_t i = 0; i < ranked.size() && i < 15; ++i) {
            const auto& r = ranked[i];
            const auto prefix = "rank[" + std::to_string(i + 1) + "].";
            out << prefix << "mod                 : " << SafeText(r.mod->name) << "\n";
            out << prefix << "score               : " << r.score << "\n";
            out << prefix << "matched_assets      : " << r.assets << "\n";
            out << prefix << "integration_order   : " << r.mod->integrationOrder << "\n";
        }
        if (ranked.size() > 15) out << "ranked_mods.omitted       : " << ranked.size() - 15 << "\n";
    }
    std::size_t matchedAssets = 0, matchedPakSources = 0, assetIndex = 0;
    out << "scan.assets.detected      : " << ordered.size() << "\n";
    for (const auto& [key, candidate] : ordered) {
        const auto prefix = "asset[" + std::to_string(++assetIndex) + "].";
        out << prefix << "object           : " << SafeText(candidate.display, 512) << "\n";
        out << prefix << "package          : " << SafeText(key, 512) << "\n";
        const auto it = found.find(key);
        const std::size_t count = it == found.end() ? 0 : it->second.size();
        out << prefix << "source_pak_hits  : " << count << "\n";
        if (!count) continue;
        ++matchedAssets;
        matchedPakSources += count;
        std::size_t hitIndex = 0;
        for (const auto& hit : it->second) {
            const auto source = prefix + "source[" + std::to_string(++hitIndex) + "].";
            out << source << "mod              : " << SafeText(hit.mod->name) << "\n";
            out << source << "provider         : " << SafeText(hit.mod->provider, 40) << "\n";
            out << source << "integration_order: " << hit.mod->integrationOrder << "\n";
            out << source << "archive          : " << SafeText(PathUtf8(hit.mod->archive.path), 1024) << "\n";
            if (!hit.member.empty()) out << source << "zip_member       : " << SafeText(hit.member, 512) << "\n";
            if (!hit.mod->modioReference.empty()) out << source << "modio_url        : " << SafeText(hit.mod->modioReference, 512) << "\n";
        }
    }
    out << "result.assets_with_sources : " << matchedAssets << "/" << ordered.size() << "\n";
    out << "result.source_pak_hits     : " << matchedPakSources << "\n";
    out << "result.snapshot_crash_match: installed_pak_size_and_mtime_match\n";

    if (missingFunction) {
        out << "\n--- blueprint function compatibility (mintfixed) ---\n";
        out << "failure.function          : " << SafeText(failure.functionName, 128) << "\n";
        out << "failure.target_class      : " << SafeText(failure.targetClass, 128) << "\n";
        out << "failure.caller_package    : "
            << (failure.callerPackage.empty() ? "not_resolved" : SafeText(failure.callerPackage, 512)) << "\n";
        std::size_t classMatches = vanillaClassCandidates.size();
        std::size_t callerMatches = 0;
        for (const auto& [order, evidence] : blueprintHits) {
            classMatches += evidence.classPackages.size();
            callerMatches += static_cast<std::size_t>(evidence.ownsCallerPackage);
        }
        out << "class.candidates           : " << classMatches << "\n";
        std::size_t candidateIndex = 0;
        for (const auto& [key, path] : vanillaClassCandidates) {
            const auto prefix = "class[" + std::to_string(++candidateIndex) + "].";
            out << prefix << "package           : " << SafeText(key, 512) << "\n";
            out << prefix << "source            : vanilla\n";
            out << prefix << "archive           : " << SafeText(path, 1024) << "\n";
            out << prefix << "evidence          : pak_index_filename\n";
        }
        for (const auto& [order, evidence] : blueprintHits) {
            if (!evidence.mod) continue;
            for (const auto& [classPackage, members] : evidence.classPackages) {
                const auto prefix = "class[" + std::to_string(++candidateIndex) + "].";
                out << prefix << "package           : " << SafeText(classPackage, 512) << "\n";
                out << prefix << "source            : mod\n";
                out << prefix << "mod               : " << SafeText(evidence.mod->name) << "\n";
                out << prefix << "integration_order : " << order << "\n";
                // Preserve ZIP member attribution even when the package is
                // a class candidate rather than a directly matching stack asset.
                const auto nestedCount = std::count_if(members.begin(), members.end(),
                    [](const auto& member) { return !member.empty(); });
                std::size_t memberNumber = 0;
                for (const auto& member : members) {
                    if (member.empty()) continue;
                    const auto field = nestedCount == 1 ? "zip_member" :
                        "zip_member[" + std::to_string(++memberNumber) + "]";
                    out << prefix << field << "       : " << SafeText(member, 512) << "\n";
                }
                out << prefix << "evidence          : pak_index_filename\n";
            }
        }
        out << "packages.caller.mod_hits  : " << callerMatches << "\n";
        std::size_t evidenceIndex = 0;
        for (const auto& [order, evidence] : blueprintHits) {
            if (!evidence.mod || (!evidence.ownsCallerPackage && evidence.classPackages.empty())) continue;
            const auto prefix = "mod_evidence[" + std::to_string(++evidenceIndex) + "].";
            out << prefix << "name                : " << SafeText(evidence.mod->name) << "\n";
            out << prefix << "integration_order   : " << order << "\n";
            out << prefix << "class_package_hits  : " << evidence.classPackages.size() << "\n";
            out << prefix << "caller_package      : " << (evidence.ownsCallerPackage ? "present" : "not_detected") << "\n";
        }
        out << "mod_evidence.total        : " << evidenceIndex << "\n";
        std::set<std::uint64_t> callerOrders, classOrders;
        for (const auto& [order, evidence] : blueprintHits) {
            if (evidence.ownsCallerPackage) callerOrders.insert(order);
            if (!evidence.classPackages.empty()) classOrders.insert(order);
        }
        std::size_t crossModPairs = 0;
        for (auto caller : callerOrders) {
            for (auto target : classOrders) {
                if (caller == target || crossModPairs >= 10) continue;
                const auto prefix = "cross_mod_pair[" + std::to_string(++crossModPairs) + "].";
                out << prefix << "caller_mod       : " << SafeText(blueprintHits.at(caller).mod->name) << "\n";
                out << prefix << "caller_order     : " << caller << "\n";
                out << prefix << "target_mod       : " << SafeText(blueprintHits.at(target).mod->name) << "\n";
                out << prefix << "target_order     : " << target << "\n";
            }
        }
        out << "cross_mod_pairs.detected  : " << crossModPairs << "\n";
        // Package-name matches are evidence of possible overlap, not proof of a cause.
        out << "verification.causation    : not_established\n";
    }
    return out.str();
}
} // namespace

bool AppendTo(const fs::path& report, const fs::path& gameExe,
              const std::vector<fs::path>& extraPaks) {
    (void)extraPaks;
    std::error_code ec;
    if (!fs::is_regular_file(report, ec) || fs::file_size(report, ec) > kMaxReportBytes || ec)
        return false;
    std::ifstream in(report, std::ios::binary);
    if (!in) return false;
    std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    const bool needsMintfixed = body.find(kMintfixedMarker) == std::string::npos;
    std::string sections;
    if (needsMintfixed) {
        // Older installations without mintfixed retain their original analysis unchanged.
        const auto loaded = mintfixed::Load(gameExe);
        if (loaded.present) {
            try { sections += AnalyzeMintfixed(loaded, body, gameExe); }
            catch (const std::exception& e) {
                sections += "\n--- mintfixed mod attribution (bpcrash.exe) ---\nstatus       : analysis_failed\nerror.message: ";
                sections += SafeText(e.what());
                sections += "\n";
            }
        }
    }
    if (sections.empty()) return false;
    std::ofstream out(report, std::ios::binary | std::ios::app);
    if (!out) return false;
    out << sections;
    out.flush();
    return static_cast<bool>(out);
}
} // namespace bpc::analysis
