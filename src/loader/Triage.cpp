#include "Triage.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <map>
#include <set>

namespace bpc::triage
{
    namespace
    {
        std::string Lower(std::string s)
        {
            for (char& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            return s;
        }

        // The last path component after '.' or ':': "/Game/A/B.B_C:Fn" -> "Fn".
        std::string_view Tail(std::string_view p)
        {
            const auto at = p.find_last_of(".:");
            return at == std::string_view::npos ? p : p.substr(at + 1);
        }

        std::string_view TrimLeft(std::string_view s)
        {
            while (!s.empty() && (s[0] == ' ' || s[0] == '\t')) s.remove_prefix(1);
            return s;
        }

        bool StartsWith(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }

        // <Root>/<Project>/Binaries/<Platform>/<Game>.exe -> <Root>/<Project>, or empty if not laid out so.
        fs::path ProjectDir(const fs::path& exe)
        {
            const fs::path bin = exe.parent_path().parent_path();
            return _wcsicmp(bin.filename().c_str(), L"Binaries") == 0 ? bin.parent_path() : fs::path();
        }

        std::vector<std::string> ReadLines(const fs::path& file)
        {
            std::vector<std::string> lines;
            std::ifstream in(file, std::ios::binary);
            for (std::string l; std::getline(in, l); )
            {
                if (!l.empty() && l.back() == '\r') l.pop_back();
                lines.push_back(std::move(l));
            }
            return lines;
        }

        // A serialized FString: int32 length, then that many bytes (UTF-8/ANSI) or -length UTF-16 units.
        bool ReadFString(const std::vector<char>& b, size_t& at, std::string& out)
        {
            if (at + 4 > b.size()) return false;
            int32_t n;
            std::memcpy(&n, &b[at], 4);
            at += 4;
            out.clear();
            if (n < 0)
            {
                const size_t units = static_cast<size_t>(-static_cast<int64_t>(n));
                if (at + units * 2 > b.size()) return false;
                for (size_t i = 0; i < units; ++i)
                {
                    const auto c = static_cast<uint16_t>(static_cast<uint8_t>(b[at + 2 * i]) | (static_cast<uint8_t>(b[at + 2 * i + 1]) << 8));
                    if (c) out += (c < 0x80) ? static_cast<char>(c) : '?';
                }
                at += units * 2;
                return true;
            }
            if (at + static_cast<size_t>(n) > b.size()) return false;
            out.assign(&b[at], static_cast<size_t>(n));
            while (!out.empty() && out.back() == 0) out.pop_back();
            at += static_cast<size_t>(n);
            return true;
        }

        template <class T> bool Get(const std::vector<char>& b, size_t& at, T& v)
        {
            if (at + sizeof(T) > b.size()) return false;
            std::memcpy(&v, &b[at], sizeof(T));
            at += sizeof(T);
            return true;
        }

        std::vector<char> ReadAt(std::ifstream& f, int64_t offset, int64_t size)
        {
            // ponytail: one read of the whole index; a 4.27 base-game index is tens of MB at most.
            if (offset < 0 || size <= 0 || size > (int64_t(1) << 30)) return {};
            std::vector<char> b(static_cast<size_t>(size));
            f.seekg(offset);
            f.read(b.data(), size);
            return f ? b : std::vector<char>{};
        }
    }

    bool FatalNames(std::string_view message, std::string& super, std::string& created)
    {
        static constexpr std::string_view kHead = "Could not find SuperStruct ", kMid = " to create ";
        const auto a = message.find(kHead);
        if (a == std::string_view::npos) return false;
        const auto rest = message.substr(a + kHead.size());
        const auto m = rest.find(kMid);
        if (m == std::string_view::npos) return false;
        super = std::string(rest.substr(0, m));
        const auto c = rest.substr(m + kMid.size());
        created = std::string(c.substr(0, c.find_first_of(" \t\r\n")));
        return !super.empty() && !created.empty();
    }

    bool LastDump(const std::vector<std::string>& lines, Dump& out)
    {
        size_t start = lines.size();
        for (size_t i = lines.size(); i-- > 0; )
            if (lines[i].find("****DumpDependencies") != std::string::npos) { start = i; break; }
        if (start == lines.size()) return false;

        out = Dump{};
        out.line = start;
        size_t j = start + 1;
        for (; j < lines.size() && lines[j].find("LogStreaming") != std::string::npos; ++j)
        {
            const auto e = lines[j].find("Error:");
            const std::string_view body = TrimLeft(std::string_view(lines[j]).substr(e == std::string::npos ? 0 : e + 6));
            if (StartsWith(body, "Export "))
            {
                const auto sp = body.find(' ', 7);   // "Export <index> <path>"
                out.exportPath = std::string(TrimLeft(body.substr(sp == std::string_view::npos ? 7 : sp)));
            }
            else if (StartsWith(body, "Linker is ")) out.linker = std::string(body.substr(10));
            else if (StartsWith(body, "Dep ")) {}
            else if (StartsWith(body, "Missing Dependency, request for "))
            {
                const auto obj = body.substr(32);
                out.missing.emplace_back(obj.substr(0, obj.find(" but it hasn't")));
            }
            else break;
        }
        out.after = lines.size() - j;
        return true;
    }

    bool Matches(const Dump& d, std::string_view super, std::string_view created)
    {
        if (Tail(d.exportPath) != created) return false;
        return std::any_of(d.missing.begin(), d.missing.end(), [&](const std::string& m) { return Tail(m) == super; });
    }

    std::string PackageOf(std::string_view path, std::string_view project)
    {
        if (StartsWith(path, "/Game/")) return std::string(path.substr(0, path.find_first_of(".:")));
        const std::string content = std::string(project) + "/Content/";
        const auto at = path.find(content);
        if (at == std::string_view::npos) return std::string(path);
        auto rest = path.substr(at + content.size());
        return "/Game/" + std::string(rest.substr(0, rest.rfind('.')));
    }

    /*
    The file list of a legacy .pak. 4.25+ (v10, v11) keeps a full directory index -- folders and
    the names in each -- at an offset the primary index names. Older versions hold
    length-prefixed names inline in the primary index, and those are picked out by shape, as
    crash_triage.py does.
    */
    std::vector<std::string> PakFiles(const fs::path& pak)
    {
        std::ifstream f(pak, std::ios::binary);
        if (!f) return {};
        f.seekg(0, std::ios::end);
        const int64_t size = f.tellg();
        const int64_t tailAt = size > 300 ? size - 300 : 0;
        std::vector<char> tail = ReadAt(f, tailAt, size - tailAt);

        static constexpr char kMagic[] = { '\xE1', '\x12', '\x6F', '\x5A' };
        size_t at = std::string::npos;
        for (size_t i = tail.size() >= 4 ? tail.size() - 4 : 0; i-- > 1; )
            if (std::memcmp(&tail[i], kMagic, 4) == 0) { at = i; break; }
        if (at == std::string::npos || tail[at - 1]) return {};   // no footer, or an encrypted index

        size_t p = at + 4;
        int32_t version = 0; int64_t indexOffset = 0, indexSize = 0;
        if (!Get(tail, p, version) || !Get(tail, p, indexOffset) || !Get(tail, p, indexSize)) return {};
        const std::vector<char> index = ReadAt(f, indexOffset, indexSize);

        std::string mount;
        size_t q = 0;
        if (!ReadFString(index, q, mount)) return {};
        std::replace(mount.begin(), mount.end(), '\\', '/');
        while (StartsWith(mount, "../")) mount.erase(0, 3);

        std::vector<std::string> out;
        if (version < 10)
        {
            for (size_t i = q; i + 4 < index.size(); ++i)
            {
                const auto n = static_cast<uint8_t>(index[i]);
                if (n < 5 || index[i + 1] || index[i + 2] || index[i + 3] || i + 4 + n > index.size()) continue;
                const std::string_view s(&index[i + 4], n);
                if (s.back() != 0 || s.find('.') == std::string_view::npos) continue;
                if (std::all_of(s.begin(), s.end() - 1, [](char c) { return c >= ' ' && c <= '~'; }))
                    out.push_back(Lower(mount + std::string(s.substr(0, n - 1))));
            }
            return out;
        }

        int32_t entries = 0, has = 0; uint64_t seed = 0;
        if (!Get(index, q, entries) || !Get(index, q, seed) || !Get(index, q, has)) return {};
        if (has) q += 8 + 8 + 20;                               // path hash index: offset, size, hash
        int64_t fdiOffset = 0, fdiSize = 0;
        if (!Get(index, q, has) || !has || !Get(index, q, fdiOffset) || !Get(index, q, fdiSize)) return {};
        const std::vector<char> fdi = ReadAt(f, fdiOffset, fdiSize);

        size_t r = 0;
        int32_t folders = 0;
        if (!Get(fdi, r, folders)) return {};
        std::string folder, name;
        for (int32_t d = 0; d < folders; ++d)
        {
            int32_t files = 0;
            if (!ReadFString(fdi, r, folder) || !Get(fdi, r, files)) break;
            while (!folder.empty() && folder[0] == '/') folder.erase(0, 1);
            for (int32_t i = 0; i < files; ++i)
            {
                int32_t entry = 0;
                if (!ReadFString(fdi, r, name) || !Get(fdi, r, entry)) return out;
                out.push_back(Lower(mount + folder + name));
            }
        }
        return out;
    }

    std::string Run(const std::string& assertMessage, const fs::path& gameExe, const std::vector<fs::path>& extraPaks)
    {
        std::string out = "--- load triage (written by bpcrash.exe after the game exited) ---\n";
        const auto done = [&](const char* why) { return out + "no verdict: " + why + "\n\n"; };

        if (assertMessage.empty()) return done("the crash is not a UE fatal error");
        std::string super, created;
        if (!FatalNames(assertMessage, super, created)) return done("the fatal is not a \"Could not find SuperStruct\" load failure");

        const fs::path projectDir = ProjectDir(gameExe);
        if (projectDir.empty()) return done("the game exe is not in <Project>/Binaries/<Platform>/, so its log is not known");
        const std::string project = projectDir.filename().string();
        const fs::path log = projectDir / "Saved" / "Logs" / (project + ".log");
        const auto lines = ReadLines(log);
        if (lines.empty()) return done(("no log at " + log.string() + " (a -nullrhi / -unattended launch may write none)").c_str());

        Dump d;
        if (!LastDump(lines, d)) return done(("the log has no ****DumpDependencies block: " + log.string()).c_str());
        out += "log     : " + log.string() + "  (last dependency dump at line " + std::to_string(d.line + 1) + ", "
             + std::to_string(d.after) + " line(s) before the end)\n";
        out += "creating: " + d.exportPath + "\n";
        out += "in file : " + d.linker + "\n";
        for (const auto& m : d.missing) out += "missing : " + m + "\n";
        if (!Matches(d, super, created))
            return done(("the log's last dependency dump is not for " + created + " / " + super + ", so it is context only").c_str());

        // The packages to look for, child first.
        std::vector<std::string> packages{ PackageOf(d.linker, project) };
        for (const auto& m : d.missing)
            if (std::find(packages.begin(), packages.end(), PackageOf(m, project)) == packages.end())
                packages.push_back(PackageOf(m, project));

        std::map<std::string, std::string> want;   // lowercased pak path -> package
        for (const auto& pkg : packages)
        {
            const std::string rel = Lower(project + "/Content/" + pkg.substr(6));
            want[rel + ".uasset"] = want[rel + ".umap"] = pkg;
        }
        std::map<std::string, std::vector<std::string>> found;
        std::set<fs::path> seen;
        std::vector<fs::path> roots{ projectDir / "Content" / "Paks", projectDir / "Mods" };
        roots.insert(roots.end(), extraPaks.begin(), extraPaks.end());
        std::error_code ec;
        for (const auto& root : roots)
        {
            std::vector<fs::path> paks;
            if (fs::is_regular_file(root, ec)) paks.push_back(root);
            else if (fs::is_directory(root, ec))
                for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
                     !ec && it != fs::recursive_directory_iterator(); it.increment(ec))
                    if (_wcsicmp(it->path().extension().c_str(), L".pak") == 0) paks.push_back(it->path());
            for (const auto& pak : paks)
            {
                if (!seen.insert(fs::weakly_canonical(pak, ec)).second) continue;
                for (const auto& file : PakFiles(pak))
                    if (const auto hit = want.find(file); hit != want.end())
                    {
                        auto& where = found[hit->second];
                        if (std::find(where.begin(), where.end(), pak.string()) == where.end()) where.push_back(pak.string());
                    }
            }
        }

        out += "paks    : (searched " + (projectDir / "Content" / "Paks").string() + ", " + (projectDir / "Mods").string()
             + (extraPaks.empty() ? "" : " and the cfg's `paks`") + ")\n";
        for (const auto& pkg : packages)
        {
            out += "  " + pkg + "\n";
            if (found[pkg].empty()) out += "      (in no pak found here)\n";
            for (const auto& pak : found[pkg]) out += "      " + pak + "\n";
        }

        const std::string& missing = d.missing.empty() ? std::string("?") : d.missing.front();
        const bool function = missing.find(':') != std::string::npos;   // Class_C:Function, not the class itself
        out += "verdict : " + created + " in " + packages[0] + " could not find "
             + (function ? "its parent function " + super + ", which the parent class as loaded does not have"
                         : "its parent class " + super + ", which was not created (its package failed to load, or no longer holds it)")
             + ".\n          Parent package: " + PackageOf(missing, project)
             + ". The two usually come from different builds: a Blueprint cooked against another version of its\n"
               "          parent, or a pak that replaced the parent. Update or remove the mod that ships the first package,\n"
               "          or the one that replaced the second (the paks above).\n\n";
        return out;
    }

    bool AppendTo(const fs::path& report, const fs::path& gameExe, const std::vector<fs::path>& extraPaks)
    {
        std::string message;
        for (const auto& l : ReadLines(report))
            if (StartsWith(l, "assert  : ")) message = l.substr(10);
        std::ofstream out(report, std::ios::binary | std::ios::app);
        out << Run(message, gameExe, extraPaks);
        return static_cast<bool>(out);
    }

    /*
    Pick the report the crash belongs to among the ones `pid` wrote: bpcrash_<date>_<time>_<pid>_<seq>_t<tid>.txt.
    Load-time self-tests are skipped. Of the first-chance reports, the last one carrying a UE fatal message wins,
    since the engine's own crash path can fault again after it; failing that, the last one.
    */
    fs::path AppendToReport(unsigned long pid, const fs::path& dir, const fs::path& gameExe,
                            const std::vector<fs::path>& extraPaks)
    {
        const std::string tag = "_" + std::to_string(pid) + "_";
        std::vector<std::pair<int, fs::path>> reports;   // (seq, path)
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(dir, ec))
        {
            const std::string name = e.path().filename().string();
            if (!StartsWith(name, "bpcrash_") || e.path().extension() != ".txt") continue;
            const auto at = name.find(tag, 23);   // past "bpcrash_YYYYMMDD_HHMMSS"
            if (at != 23) continue;
            reports.emplace_back(std::atoi(name.c_str() + at + tag.size()), e.path());
        }
        std::sort(reports.begin(), reports.end());

        fs::path pick, fatal;
        for (const auto& [seq, path] : reports)
        {
            const auto lines = ReadLines(path);
            if (lines.size() < 2 || !StartsWith(lines[1], "reason  : first-chance")) continue;
            pick = path;
            if (std::any_of(lines.begin(), lines.end(), [](const std::string& l) { return StartsWith(l, "assert  : "); }))
                fatal = path;
        }
        if (!fatal.empty()) pick = fatal;
        if (!pick.empty()) AppendTo(pick, gameExe, extraPaks);
        return pick;
    }
}
