#include "AssetAnalysis.h"
#include "Triage.h"
#include "MintfixedContext.h"
#include "BlueprintRefs.h"

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
constexpr std::string_view kMarker = "--- asset overlap analysis (bpcrash.exe) ---";
constexpr std::string_view kMintfixedMarker = "--- mintfixed mod attribution (bpcrash.exe) ---";
constexpr size_t kMaxReportBytes = 16 * 1024 * 1024;
constexpr size_t kMaxPaths = 48;
constexpr size_t kMaxPaks = 8192;

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool Contains(const std::string& line, std::string_view term) {
    return line.find(term) != std::string::npos;
}

std::string PathUtf8(const fs::path& p) {
    // Windows file paths are UTF-16; explicit conversion prevents locale dependence.
    const auto str = p.u8string();
    return std::string(str.begin(), str.end());
}

std::string Basename(const fs::path& p) { return PathUtf8(p.filename()); }

std::string ProjectName(const fs::path& gameExe) {
    // .../<project>/Binaries/<platform>/<exe> (DRG uses FSD).
    const auto bin = gameExe.parent_path().parent_path();
    if (Lower(Basename(bin)) != "binaries") return {};
    return Lower(Basename(bin.parent_path()));
}

fs::path ProjectPath(const fs::path& gameExe) {
    const auto bin = gameExe.parent_path().parent_path();
    if (Lower(Basename(bin)) != "binaries") return {};
    return bin.parent_path();
}

// In a crash report: /Game/A/B.B_C:Function -> fsd/content/a/b.
// In a pak index: ../../../FSD/Content/A/B.uasset -> fsd/content/a/b.
std::string NormalizePackage(std::string value, const std::string& project) {
    std::replace(value.begin(), value.end(), '\\', '/');
    value = Lower(value);
    const auto delimiter = value.find_first_of(" \r\n\t\"'<>|,;(){}[]");
    if (delimiter != std::string::npos) value.resize(delimiter);
    auto stripExtension = [&]() {
        for (const std::string ext : {".uasset", ".uexp", ".umap", ".ubulk", ".uptnl"}) {
            if (value.size() >= ext.size() && value.compare(value.size() - ext.size(), ext.size(), ext) == 0) {
                value.resize(value.size() - ext.size());
                return;
            }
        }
    };
    stripExtension();
    auto at = value.find("/game/");
    if (at != std::string::npos) {
        value = project + "/content/" + value.substr(at + 6);
    } else {
        at = value.find("/engine/");
        if (at != std::string::npos) {
            value = "engine/content/" + value.substr(at + 8);
        } else {
            // Pak entries may begin with ../../../ or have a mount prefix.
            const auto proj = project + "/content/";
            at = value.find(proj);
            if (at == std::string::npos) {
                at = value.find("engine/content/");
                if (at == std::string::npos) return {};
            }
            value = value.substr(at);
        }
    }
    // UE object suffixes are not part of the package path.
    const auto slash = value.find_last_of('/');
    const auto dot = value.find('.', slash == std::string::npos ? 0 : slash);
    if (dot != std::string::npos) value.resize(dot);
    while (!value.empty() && (value.back() == '/' || value.back() == ':')) value.pop_back();
    return value;
}

struct Candidate {
    std::string display;
    std::set<std::string> reasons;
    int weight = 0;
};

std::map<std::string, Candidate> FindCandidates(const std::string& report, const std::string& project) {
    std::map<std::string, Candidate> found;
    // Scan only syntactically valid Unreal package names. Never assume that a path in a
    // locals dump is necessarily the cause: evidence is explicitly labeled.
    const std::regex gamePath(R"((/(?:Game|Engine)/[A-Za-z0-9_./:\-]+))", std::regex::icase);
    const std::regex contentPath(R"((([A-Za-z0-9_]+[/\\]Content[/\\][A-Za-z0-9_./\\\-]+\.(?:uasset|uexp|umap))))", std::regex::icase);
    std::istringstream input(report);
    std::string line;
    size_t count = 0;
    while (std::getline(input, line) && count++ < 150000) {
        const std::string low = Lower(line);
        int weight = 1;
        if (Contains(low, "assert") || Contains(low, "creating:") || Contains(low, "missing:") ||
            Contains(low, "in file") || Contains(low, "fatal error") || Contains(low, "exception")) {
            weight = 3;
        } else if (Contains(low, "blueprint") || Contains(low, "function") ||
                   Contains(low, "self") || Contains(low, "frame") || Contains(low, "opcode")) {
            weight = 2;
        }
        auto add = [&](const std::string& original) {
            const std::string canonical = NormalizePackage(original, project);
            if (canonical.empty()) return;
            if (!found.count(canonical) && found.size() >= kMaxPaths) return;
            auto& record = found[canonical];
            if (record.display.empty()) record.display = original;
            record.weight = std::max(record.weight, weight);
            if (weight == 3) record.reasons.insert("fatal/load context");
            else if (weight == 2) record.reasons.insert("Blueprint stack/context");
            else record.reasons.insert("mentioned in report (weak evidence)");
        };
        for (auto it = std::sregex_iterator(line.begin(), line.end(), gamePath);
             it != std::sregex_iterator(); ++it) add((*it)[1]);
        for (auto it = std::sregex_iterator(line.begin(), line.end(), contentPath);
             it != std::sregex_iterator(); ++it) add((*it)[1]);
    }
    return found;
}

std::vector<fs::path> FindPaks(const fs::path& exe, const std::vector<fs::path>& extraPaks) {
    std::vector<fs::path> roots;
    const auto dir = ProjectPath(exe);
    if (!dir.empty()) {
        roots.push_back(dir / "Content" / "Paks");
        roots.push_back(dir / "Mods");
    }
    roots.insert(roots.end(), extraPaks.begin(), extraPaks.end());
    std::vector<fs::path> result;
    std::set<std::string> seen;
    for (const auto& root : roots) {
        std::error_code ec;
        if (fs::is_regular_file(root, ec)) {
            if (Lower(root.extension().string()) == ".pak" && seen.insert(Lower(PathUtf8(root.lexically_normal()))).second)
                result.push_back(root);
            continue;
        }
        if (!fs::is_directory(root, ec)) continue;
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        while (it != end && result.size() < kMaxPaks) {
            if (ec) { ec.clear(); it.increment(ec); continue; }
            if (it.depth() > 16) { it.disable_recursion_pending(); it.increment(ec); continue; }
            if (it->is_regular_file(ec) && Lower(it->path().extension().string()) == ".pak") {
                const auto path = it->path();
                if (seen.insert(Lower(PathUtf8(path.lexically_normal()))).second) result.push_back(path);
            }
            it.increment(ec);
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::string Analyze(const std::string& report, const fs::path& gameExe, const std::vector<fs::path>& extraPaks) {
    std::ostringstream out;
    out << "\n" << kMarker << "\n";
    const auto project = ProjectName(gameExe);
    if (project.empty()) {
        out << "status                    : invalid_game_executable_layout\n";
        return out.str();
    }
    auto candidates = FindCandidates(report, project);
    if (candidates.empty()) {
        out << "scan.assets.detected      : 0\n";
        out << "status                    : no_recognized_asset_paths\n";
        return out.str();
    }
    auto paks = FindPaks(gameExe, extraPaks);
    std::map<std::string, std::vector<fs::path>> hits;
    size_t unreadable = 0;
    // A pak index is read once, then used to match every candidate. If a pak is encrypted,
    // absent or unsupported, it cannot be exonerated; record this limitation.
    for (const auto& pak : paks) {
        auto files = bpc::triage::PakFiles(pak);
        if (files.empty()) { ++unreadable; continue; }
        std::set<std::string> matched;
        for (const auto& file : files) {
            const auto key = NormalizePackage(file, project);
            if (candidates.count(key)) matched.insert(key);
        }
        for (const auto& key : matched) hits[key].push_back(pak);
    }
    std::vector<std::pair<std::string, Candidate>> ordered(candidates.begin(), candidates.end());
    std::stable_sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        return a.second.weight > b.second.weight;
    });
    out << "scan.paks.total           : " << paks.size() << "\n";
    out << "scan.paks.index_readable  : " << paks.size() - unreadable << "\n";
    out << "scan.paks.index_unreadable: " << unreadable << "\n";
    out << "scan.assets.detected      : " << ordered.size() << "\n";
    std::size_t totalPakHits = 0, assetsWithHits = 0, assetIndex = 0;
    for (const auto& [key, candidate] : ordered) {
        ++assetIndex;
        const auto prefix = "asset[" + std::to_string(assetIndex) + "].";
        out << prefix << "object           : " << candidate.display << "\n";
        out << prefix << "package          : " << key << "\n";
        out << prefix << "evidence         : ";
        bool first = true;
        for (const auto& reason : candidate.reasons) {
            if (!first) out << ", ";
            out << reason;
            first = false;
        }
        out << "\n";
        const auto& sources = hits[key];
        totalPakHits += sources.size();
        if (!sources.empty()) ++assetsWithHits;
        out << prefix << "pak_matches      : " << sources.size() << "\n";
        std::size_t index = 0;
        for (const auto& path : sources) {
            const auto n = Lower(Basename(path));
            out << prefix << "pak[" << ++index << "].path      : " << PathUtf8(path) << "\n";
            if (n == "mods_p.pak")
                out << prefix << "pak[" << index << "].type      : merged_archive\n";
        }
    }
    out << "result.assets_with_pak_hits: " << assetsWithHits << "\n";
    out << "result.total_pak_hits      : " << totalPakHits << "\n";
    out << "result.active_package_winner: not_determined\n";
    return out.str();
}
std::string SafeText(std::string value, std::size_t limit = 256) {
    if (value.size() > limit) value.resize(limit);
    for (char& c : value) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
    return value;
}

bool LooksLikeZip(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    char magic[4]{};
    in.read(magic, 4);
    return in.gcount() == 4 && magic[0] == 'P' && magic[1] == 'K' &&
           (magic[2] == 3 || magic[2] == 5 || magic[2] == 7) &&
           (magic[3] == 4 || magic[3] == 6 || magic[3] == 8);
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
        out << "status                  : invalid_context\n";
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
    out << "context.installed_mods    : " << context.installedMods.size() << "\n";
    if (candidates.empty() && !missingFunction) {
        out << "scan.assets.detected      : 0\n";
        out << "status                    : no_recognized_assets_or_missing_functions\n";
        return out.str();
    }

    struct BlueprintModEvidence {
        const mintfixed::Mod* mod = nullptr;
        std::set<std::string> classPackages;
        bool ownsCallerPackage = false;
        bool functionNameMention = false;
        bool classNameMention = false;
        bool incompleteScan = false;
    };
    std::map<std::uint64_t, BlueprintModEvidence> blueprintHits;
    std::map<std::string, std::string> vanillaClassCandidates;
    std::map<std::string, std::vector<ModHit>> found;
    std::size_t checked = 0, unreadable = 0, changed = 0, zipPaks = 0, badZipEntries = 0;
    for (const auto& mod : context.installedMods) {
        std::error_code ec;
        if (!mod.archive.exists || !fs::is_regular_file(mod.archive.path, ec) || ec) {
            ++unreadable;
            continue;
        }
        const auto size = fs::file_size(mod.archive.path, ec);
        if (ec || size != mod.archive.byteSize) {
            ++changed; // Don't match an archive that differs from the installation snapshot.
            continue;
        }
        ++checked;
        auto checkFiles = [&](const std::vector<std::string>& files, const std::string& member) {
            std::set<std::string> matches;
            for (const auto& file : files) {
                const auto key = NormalizePackage(file, project);
                if (candidates.count(key)) matches.insert(key);
                if (missingFunction && !failure.callerPackage.empty() && key == failure.callerPackage) {
                    auto& evidence = blueprintHits[mod.integrationOrder];
                    evidence.mod = &mod;
                    evidence.ownsCallerPackage = true;
                }
            }
            for (const auto& key : matches) found[key].push_back(ModHit{&mod, member});
            if (missingFunction) {
                const auto classes = blueprint::ClassPathCandidates(files, failure.targetClass, project);
                if (!classes.empty()) {
                    auto& evidence = blueprintHits[mod.integrationOrder];
                    evidence.mod = &mod;
                    evidence.classPackages.insert(classes.begin(), classes.end());
                }
            }
        };
        auto checkSymbols = [&](const blueprint::SymbolEvidence& symbols) {
            if (!missingFunction) return;
            if (!symbols.functionName && !symbols.className && symbols.complete) return;
            auto& evidence = blueprintHits[mod.integrationOrder];
            evidence.mod = &mod;
            evidence.functionNameMention |= symbols.functionName;
            evidence.classNameMention |= symbols.className;
            evidence.incompleteScan |= !symbols.complete;
        };
        const bool zip = mod.nestedPaksMustBeScanned || mod.archiveType == "zip" || LooksLikeZip(mod.archive.path);
        if (zip) {
            const auto stats = mintfixed::VisitZipPaks(mod.archive.path,
                [&](const std::string& member, const std::vector<unsigned char>& data) {
                    checkFiles(triage::PakFilesFromBytes(data), member);
                    if (missingFunction) checkSymbols(blueprint::SearchBytes(data, failure));
                });
            zipPaks += stats.decoded;
            badZipEntries += stats.skipped;
            if (!stats.warning.empty() || stats.pakEntries == 0 || stats.decoded == 0) ++unreadable;
        } else {
            const auto files = triage::PakFiles(mod.archive.path);
            if (files.empty()) ++unreadable;
            else checkFiles(files, "");
            if (missingFunction) checkSymbols(blueprint::SearchFile(mod.archive.path, failure));
        }
    }
    if (missingFunction) {
        // FName generated class names usually map to an identically named .uasset.
        // Search the vanilla PAK index by filename, not the runtime /Engine/Transient path.
        const auto vanilla = ProjectPath(gameExe) / "Content" / "Paks" / "FSD-WindowsNoEditor.pak";
        std::error_code vanillaError;
        if (fs::is_regular_file(vanilla, vanillaError)) {
            for (const auto& key : blueprint::ClassPathCandidates(
                     triage::PakFiles(vanilla), failure.targetClass, project))
                vanillaClassCandidates.emplace(key, PathUtf8(vanilla));
        }
    }
    out << "scan.archives.opened      : " << checked << "\n";
    out << "scan.nested_zip_paks      : " << zipPaks << "\n";
    out << "scan.archives.unreadable  : " << unreadable << "\n";
    out << "scan.archives.size_changed: " << changed << "\n";
    out << "scan.zip_entries.skipped  : " << badZipEntries << "\n";
    out << "integrity.archive_size    : checked\n";
    out << "integrity.sha256          : not_revalidated\n";
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
        out << "ranked_mods.score_weights : fatal=3, blueprint=2, mention=1\n";
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
    out << "result.active_package_winner: not_determined\n";
    out << "result.snapshot_crash_match: not_validated\n";

    if (missingFunction) {
        out << "\n--- blueprint function compatibility (mintfixed) ---\n";
        out << "failure.type              : missing_blueprint_function\n";
        out << "failure.function          : " << SafeText(failure.functionName, 128) << "\n";
        out << "failure.target_class      : " << SafeText(failure.targetClass, 128) << "\n";
        out << "failure.caller_package    : "
            << (failure.callerPackage.empty() ? "not_resolved" : SafeText(failure.callerPackage, 512)) << "\n";
        std::size_t classMatches = vanillaClassCandidates.size();
        std::size_t functionMentions = 0, classMentions = 0, callerMatches = 0, incomplete = 0;
        for (const auto& [order, evidence] : blueprintHits) {
            classMatches += evidence.classPackages.size();
            functionMentions += static_cast<std::size_t>(evidence.functionNameMention);
            classMentions += static_cast<std::size_t>(evidence.classNameMention);
            callerMatches += static_cast<std::size_t>(evidence.ownsCallerPackage);
            incomplete += static_cast<std::size_t>(evidence.incompleteScan);
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
            for (const auto& classPackage : evidence.classPackages) {
                const auto prefix = "class[" + std::to_string(++candidateIndex) + "].";
                out << prefix << "package           : " << SafeText(classPackage, 512) << "\n";
                out << prefix << "source            : mod\n";
                out << prefix << "mod               : " << SafeText(evidence.mod->name) << "\n";
                out << prefix << "integration_order : " << order << "\n";
                out << prefix << "evidence          : pak_index_filename\n";
            }
        }
        out << "symbols.function.mod_hits : " << functionMentions << "\n";
        out << "symbols.class.mod_hits    : " << classMentions << "\n";
        out << "symbols.caller.mod_hits   : " << callerMatches << "\n";
        out << "symbols.scan_incomplete   : " << incomplete << "\n";
        std::size_t evidenceIndex = 0;
        for (const auto& [order, evidence] : blueprintHits) {
            if (!evidence.mod || (!evidence.functionNameMention && !evidence.classNameMention &&
                                  !evidence.ownsCallerPackage && evidence.classPackages.empty() &&
                                  !evidence.incompleteScan)) continue;
            const auto prefix = "mod_evidence[" + std::to_string(++evidenceIndex) + "].";
            out << prefix << "name                : " << SafeText(evidence.mod->name) << "\n";
            out << prefix << "integration_order   : " << order << "\n";
            out << prefix << "class_package_hits  : " << evidence.classPackages.size() << "\n";
            out << prefix << "target_class_name   : " << (evidence.classNameMention ? "present" : "not_detected") << "\n";
            out << prefix << "missing_function    : " << (evidence.functionNameMention ? "present" : "not_detected") << "\n";
            out << prefix << "caller_package      : " << (evidence.ownsCallerPackage ? "present" : "not_detected") << "\n";
            out << prefix << "scan               : " << (evidence.incompleteScan ? "incomplete" : "completed") << "\n";
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
        out << "verification.pak_names    : indexed_filename_and_raw_name_scan\n";
        out << "verification.bytecode     : not_parsed\n";
        out << "verification.runtime_class: not_available\n";
        out << "verification.active_winner: not_determined\n";
        out << "verification.causation    : not_established\n";
    }
    return out.str();
}
} // namespace

bool AppendTo(const fs::path& report, const fs::path& gameExe,
              const std::vector<fs::path>& extraPaks) {
    std::error_code ec;
    if (!fs::is_regular_file(report, ec) || fs::file_size(report, ec) > kMaxReportBytes || ec)
        return false;
    std::ifstream in(report, std::ios::binary);
    if (!in) return false;
    std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    const bool needsOverlap = body.find(kMarker) == std::string::npos;
    const bool needsMintfixed = body.find(kMintfixedMarker) == std::string::npos;
    std::string sections;
    if (needsOverlap) sections += Analyze(body, gameExe, extraPaks);
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
