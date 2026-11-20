/*
selftest.cpp

The one check that runs without a game. Most of the tool needs a live UE process, but the pure
decoders do not: the pattern scanner, the FName pool reader, the opcode table, and the dbghelp
path. All of them are hand-rolled and all of them fail silently if they drift, and a synthetic
name pool is enough to catch that.

  cmake --build build --config Release --target selftest && build/Release/selftest.exe
*/

#include <cstdio>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../src/dll/Bytecode.h"
#include "../src/dll/NamePool.h"
#include "../src/dll/Platform.h"
#include "../src/dll/Symbols.h"
#include "../src/dll/Ue.h"
#include "../src/loader/Triage.h"
#include "../src/loader/AssetAnalysis.h"
#include "../src/loader/MintfixedContext.h"
#include "../src/loader/FileModifiedUnixMs.h"
#include "../src/loader/BlueprintRefs.h"
#include "../src/loader/AnalysisCommon.h"
#include <nlohmann/json.hpp>

using namespace bpc;

/* We do not use assert() here, because this builds in Release, where NDEBUG compiles the checks
   and the calls inside them out of existence and leaves a test that passes by doing nothing. */
static int g_fails = 0;

static bool Check(bool cond, const char* expr, int line)
{
    if (!cond) { std::printf("FAIL selftest.cpp:%d  %s\n", line, expr); ++g_fails; }
    return cond;
}
#define CHECK(expr) Check(!!(expr), #expr, __LINE__)

namespace
{
    alignas(16) uint8_t g_block[4096];

    /* A stand-in FNameEntryAllocator, laid out like the engine's so the reader runs against its
       real offsets rather than hand-set globals:
         +0x08 CurrentBlock (read live on every lookup)   +0x10 Blocks[] */
    alignas(16) uint8_t g_pool[0x40];

    // Write an FNameEntry at `off` (in entry-stride units of 2 bytes) and return that offset.
    uint32_t PutName(uint32_t off, const char* text)
    {
        const uint16_t len = static_cast<uint16_t>(::strlen(text));
        uint8_t* e = g_block + static_cast<size_t>(off) * 2;
        *reinterpret_cast<uint16_t*>(e) = static_cast<uint16_t>(len << 6);   // bit0 = wide, clear
        ::memcpy(e + 2, text, len);
        return off;
    }

    void TestNames()
    {
        *reinterpret_cast<uint32_t*>(g_pool + 0x08) = 0;                   // CurrentBlock
        *reinterpret_cast<uint8_t**>(g_pool + 0x10) = g_block;             // Blocks[0]
        names::g_pool = g_pool;
        names::g_blocks = reinterpret_cast<uint8_t**>(g_pool + 0x10);
        names::g_blockCount = 0;
        names::g_ok = true;

        const uint32_t none = PutName(0, "None");
        const uint32_t foo = PutName(8, "Foo");

        char out[64];
        names::Decode({ static_cast<int32_t>(none), 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "None") == 0);

        names::Decode({ static_cast<int32_t>(foo), 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "Foo") == 0);

        // FName.Number is 1-based on the wire, so Number 4 renders as _3.
        names::Decode({ static_cast<int32_t>(foo), 4 }, out, sizeof(out));
        CHECK(::strcmp(out, "Foo_3") == 0);

        // A block index past the live CurrentBlock must degrade, and say which index failed.
        names::Decode({ 0x7F000000, 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "<name?#7F000000>") == 0);

        /* This is what guards the live-count read: a name in a block allocated after bind time
           has to resolve, because the pool grows for the whole session. */
        *reinterpret_cast<uint8_t**>(g_pool + 0x18) = g_block;             // Blocks[1]
        *reinterpret_cast<uint32_t*>(g_pool + 0x08) = 1;                   // CurrentBlock grew
        names::Decode({ static_cast<int32_t>((1u << 16) | foo), 0 }, out, sizeof(out));
        CHECK(::strcmp(out, "Foo") == 0);

        std::printf("names   ok\n");
    }

    void TestPattern()
    {
        const uint8_t hay[] = { 0x90, 0x48, 0x8D, 0x0D, 0x11, 0x22, 0x33, 0x44, 0xE8, 0x90 };

        plat::PatternByte pat[8];
        CHECK(plat::ParsePattern("48 8D 0D ? ? ? ? E8", pat, 8) == 8);
        CHECK(pat[0].value == 0x48 && !pat[0].wild);
        CHECK(pat[3].wild);
        CHECK(plat::ParsePattern("48 ZZ", pat, 8) == 0);          // malformed
        CHECK(plat::ParsePattern("48 8D 0D", pat, 2) == 0);       // exceeds capacity

        const uint8_t* hit = plat::FindPatternIn(hay, sizeof(hay), "48 8D 0D ? ? ? ? E8");
        CHECK(hit == hay + 1);
        CHECK(plat::FindPatternIn(hay, sizeof(hay), "48 8D 0E") == nullptr);

        // rip-relative: lea is 7 bytes, disp32 at +3.
        CHECK(plat::RipTarget(hit, 3, 7) == reinterpret_cast<uintptr_t>(hit) + 7 + 0x44332211);

        CHECK(plat::BadRead(nullptr));
        CHECK(!plat::BadRead(hay, sizeof(hay)));

        std::printf("pattern ok\n");
    }

    void TestBytecode()
    {
        char out[128];
        const uint8_t nothing = 0x0B;
        bytecode::Describe(&nothing, out, sizeof(out));
        CHECK(::strcmp(out, "EX_Nothing") == 0);

        const uint8_t unknown = 0x77;
        bytecode::Describe(&unknown, out, sizeof(out));
        CHECK(::strcmp(out, "EX_?") == 0);

        bytecode::Describe(nullptr, out, sizeof(out));
        CHECK(::strcmp(out, "<code?>") == 0);

        std::printf("opcode  ok\n");
    }

    /* Symbolication against this exe's own PDB. Covers the whole dbghelp path end to end: dynamic
       load, SymInitialize, module attribution and name lookup, with no game involved. */
    void TestSymbols()
    {
        char out[512];

        CHECK(!sym::Resolve(nullptr, out, sizeof(out)));
        int onTheStack = 0;
        CHECK(!sym::Resolve(&onTheStack, out, sizeof(out)));   // the stack is in no module

        const bool ready = sym::Init();
        std::printf("symbols %s\n  status: %s\n", ready ? "ok" : "off", sym::Status());
        // The selftest executable is built with /DEBUG and ships a PDB.
        // Initialization failure is a test failure, not permission to skip
        // the precise symbol-resolution assertion.
        CHECK(ready);

        const void* here = reinterpret_cast<const void*>(&sym::Init);
        CHECK(sym::Resolve(here, out, sizeof(out)));
        const std::string ownSymbol(out);
        CHECK(ownSymbol.find("selftest.exe") != std::string::npos);
        std::printf("  self  : %s\n", ownSymbol.c_str());
        CHECK(ownSymbol.find('!') != std::string::npos);
        CHECK(ownSymbol.find(" (nearest: ") == std::string::npos);
        CHECK(ownSymbol.find("Init") != std::string::npos);

        const void* sleepFn = plat::ImportedFunction(L"kernel32.dll", "Sleep");
        CHECK(sym::Resolve(sleepFn, out, sizeof(out)));
        CHECK(::_strnicmp(out, "kernel32", 8) == 0);
        std::printf("  export: %s\n", out);

    }

    /*
    The OS layer behind Platform.h. Only the parts with a decision in them: the section filter and
    the cap. Everything the filter feeds -- the pattern scan above, the GObjects walk in Endpoint --
    silently finds nothing if this returns an empty or wrong set, which is the failure mode worth a
    check of its own.
    */
    void TestSections()
    {
        plat::Section all[plat::kMaxSections]{};
        const size_t n = plat::Sections(all, plat::kMaxSections, plat::SectionKind::Any);
        CHECK(n > 0);

        for (size_t i = 0; i < n; ++i)
        {
            CHECK(all[i].start != nullptr);
            CHECK(plat::InModule(all[i].start));
        }

        // This exe has code in it, and every executable section is one of the sections.
        plat::Section exec[plat::kMaxSections]{};
        const size_t e = plat::Sections(exec, plat::kMaxSections, plat::SectionKind::Executable);
        CHECK(e > 0 && e <= n);
        CHECK(plat::IsExecutable(exec[0].start));

        // A short buffer truncates rather than overruns.
        plat::Section one{};
        CHECK(plat::Sections(&one, 1, plat::SectionKind::Any) == 1);
        CHECK(plat::Sections(&one, 0, plat::SectionKind::Any) == 0);

        std::printf("section ok\n");
    }
}

namespace
{
    // The log reading behind the load triage, on a dump as DRG writes it (CL-135784).
    void TestTriage()
    {
        const std::string e = "[2026.03.17-19.10.56:756][497]LogStreaming: Error: ";
        const std::vector<std::string> lines{ "noise", e + "****DumpDependencies [Dependencies]:",
            e + "    Export 4 /Game/M/WBP_Child.WBP_Child_C:Setup",
            e + "    Linker is ../../../FSD/Content/M/WBP_Child.uasset",
            e + "        Dep S_BEFORE_S Import    43   /Game/P/WBP_Base.WBP_Base_C:Setup",
            e + "Missing Dependency, request for /Game/P/WBP_Base.WBP_Base_C:Setup but it hasn't been created yet." };
        triage::Dump d;
        CHECK(triage::LastDump(lines, d));
        CHECK(d.line == 1 && d.after == 0);
        CHECK(d.exportPath == "/Game/M/WBP_Child.WBP_Child_C:Setup");
        CHECK(d.linker == "../../../FSD/Content/M/WBP_Child.uasset");
        CHECK(d.missing.size() == 1 && d.missing[0] == "/Game/P/WBP_Base.WBP_Base_C:Setup");

        std::string super, created;
        CHECK(triage::FatalNames("Fatal error: [File:Unknown] [Line: 3159] Could not find SuperStruct Setup to create Setup",
                                 super, created));
        CHECK(super == "Setup" && created == "Setup");
        CHECK(triage::Matches(d, super, created));
        CHECK(!triage::Matches(d, "ReceiveTick", "ReceiveTick"));
        CHECK(!triage::FatalNames("Assertion failed: x", super, created));

        CHECK(triage::PackageOf(d.linker, "FSD") == "/Game/M/WBP_Child");
        CHECK(triage::PackageOf(d.missing[0], "FSD") == "/Game/P/WBP_Base");

        std::vector<std::string> none{ "a", "b" };
        CHECK(!triage::LastDump(none, d));
        std::printf("triage ok\n");
    }
}

namespace {
void TestMintfixedContext()
{
    namespace fs = std::filesystem;
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path temp = fs::temp_directory_path() / ("bpcrash-mintfixed-v2-" + std::to_string(unique));
    struct Cleanup { fs::path path; ~Cleanup() { std::error_code ec; fs::remove_all(path, ec); } } cleanup{temp};
    try {
        const fs::path bin = temp / "FSD" / "Binaries" / "Win64";
        fs::create_directories(bin / "mintfixed-bpcrash");
        const fs::path exe = bin / "FSD-Win64-Shipping.exe";
        { std::ofstream out(exe); out << "test"; }
        const auto jsonEscape = [](const fs::path& path) {
            const auto chars = path.u8string();
            std::string value;
            for (auto c : chars) {
                const auto ch = static_cast<char>(c);
                if (ch == '\\' || ch == '"') value.push_back('\\');
                value.push_back(ch);
            }
            return value;
        };
        const fs::path installed = temp / "FSD" / "Content" / "Paks" / "mods_P.pak";
        fs::create_directories(installed.parent_path());
        { std::ofstream out(installed, std::ios::binary); out << "sample merged PAK"; }
        const auto testFingerprint = [&]() {
            using nlohmann::json;
            const auto ms = mintfixed::FileModifiedUnixMs(installed);
            CHECK(ms.has_value());
            return json{{"path", shared::PathUtf8(installed)}, {"exists", true},
                        {"byte_size", fs::file_size(installed)}, {"modified_unix_ms", ms.value_or(0ULL)}};
        };
        const auto stampInstalledPak = [&](std::string data) {
            auto json = nlohmann::json::parse(data);
            json["installed_pak"] = testFingerprint();
            for (auto& mod : json["installed_mods"]) {
                if (!mod["archive"].contains("modified_unix_ms"))
                    mod["archive"]["modified_unix_ms"] = nullptr;
            }
            return json.dump();
        };
        const fs::path context = bin / "mintfixed-bpcrash" / "crash_context.json";
        // These source archives deliberately do not exist. v2 must rely ONLY
        // on the installation snapshot, without reopening either source file.
        {
            std::ostringstream out;
            out << R"({"schema_version":2,"producer":"mintfixed","captured_after_successful_install":true,"generated_unix_ms":123,"installed_pak":{"path":"merged","exists":true,"byte_size":42},"installed_mods":[)"
                << "{\"name\":\"Direct PAK\",\"provider\":\"file\",\"integration_order\":0,\"archive\":{\"path\":\""
                << jsonEscape(temp/"does-not-exist.pak")
                << "\",\"exists\":false,\"byte_size\":0},\"archive_type\":\"pak_or_unknown\",\"archive_index\":{\"status\":\"complete\",\"paks\":[{\"member\":null,\"complete\":true,\"packages\":[\"../../../FSD/Content/WeaponsNTools/DualMachinePistols/WPN_DualMPs.uasset\"]}]}} ,"
                << "{\"name\":\"Nested PAK\",\"provider\":\"modio\",\"integration_order\":1,\"archive\":{\"path\":\""
                << jsonEscape(temp/"no-zip-needed")
                << "\",\"exists\":false,\"byte_size\":0},\"archive_type\":\"zip\",\"modio_reference\":\"https://mod.io/g/drg/m/test\",\"archive_index\":{\"status\":\"complete\",\"paks\":[{\"member\":\"mods/packed.pak\",\"complete\":true,\"packages\":[\"../../../FSD/Content/WeaponsNTools/_Crosshairs/NewCrosshairs/HUD_CroNewGrenadeLauncher.uasset\"]}]}}]}";
            std::ofstream manifestOut(context);
            manifestOut << stampInstalledPak(out.str());
        }
        const auto loaded = mintfixed::Load(exe);
        CHECK(loaded.valid && loaded.context.schemaVersion == 2);
        CHECK(loaded.context.installedMods.size() == 2);
        const fs::path report = temp / "crash.txt";
        {
            std::ofstream out(report);
            out << "assert  : Failed to find function ChangeColorOfDot in HUD_CroNewGrenadeLauncher_C "
                   "/Game/Maps/SpaceRig/LVL_SpaceRig.LVL_SpaceRig.PersistentLevel:HUD_CroNewGrenadeLauncher_C_123\n"
                   "#0  /Game/WeaponsNTools/DualMachinePistols/WPN_DualMPs.WPN_DualMPs_C:ExecuteUbergraph\n";
        }
        CHECK(triage::AppendTo(report, exe, {}));
        CHECK(triage::AppendTo(report, exe, {}));
        std::ifstream in(report);
        const std::string result((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const auto count = [&](std::string_view marker) {
            std::size_t occurrences = 0, at = 0;
            while ((at = result.find(marker, at)) != std::string::npos) { ++occurrences; at += marker.size(); }
            return occurrences;
        };
        CHECK(count("--- load triage (written by bpcrash.exe after the game exited) ---") == 1);
        CHECK(count("--- mintfixed mod attribution (bpcrash.exe) ---") == 1);
        CHECK(count("--- blueprint function compatibility (mintfixed) ---") == 1);
        CHECK(result.find("context.schema_version   : 2") != std::string::npos);
        CHECK(result.find("scan.source                   : mintfixed_manifest_v2") != std::string::npos);
        CHECK(result.find("scan.archives.indexed         : 2") != std::string::npos);
        CHECK(result.find("scan.nested_zip_paks          : 1") != std::string::npos);
        CHECK(result.find("Nested PAK") != std::string::npos);
        // A nested PAK used only as a Blueprint class candidate must still
        // reveal the precise ZIP member that supplied the class.
        CHECK(result.find(".zip_member       : mods/packed.pak") != std::string::npos);
        CHECK(result.find("Direct PAK") != std::string::npos);
        CHECK(result.find("verification.pak_names") == std::string::npos);
        CHECK(result.find("symbols.function.mod_hits") == std::string::npos);
        CHECK(result.find("target_class_name") == std::string::npos);
        CHECK(result.find("integrity.archive_sha256") == std::string::npos);
        CHECK(result.find("fsd/content/maps/spacerig") == std::string::npos);
        CHECK(result.find("verification.causation    : not_established") != std::string::npos);
        CHECK(result.find("--- asset overlap analysis") == std::string::npos);

        // v1 must NOT be silently treated as indexed v2 data.
        { std::ofstream out(context); out << R"({"schema_version":1,"producer":"mintfixed","captured_after_successful_install":true})"; }
        CHECK(!mintfixed::Load(exe).valid);
        // Incomplete indexes must not claim complete coverage.
        { std::ofstream out(context); out << R"({"schema_version":2,"producer":"mintfixed","captured_after_successful_install":true,"generated_unix_ms":1,"installed_pak":{"path":"p","exists":true,"byte_size":1},"installed_mods":[{"name":"Bad","provider":"file","integration_order":0,"archive":{"path":"p","exists":true,"byte_size":1},"archive_type":"zip","archive_index":{"status":"complete","paks":[]}}]})"; }
        CHECK(!mintfixed::Load(exe).valid);

        // Use the library parser for JSON syntax/Unicode without weakening
        // the existing strict schema, duplicate-key or resource-limit checks.
        const std::string minimal = stampInstalledPak(R"({"schema_version":2,"producer":"mintfixed","captured_after_successful_install":true,"generated_unix_ms":9223372036854775808,"installed_pak":{"path":"merged","exists":true,"byte_size":42},"installed_mods":[]})");
        const auto writeContext = [&](const std::string& bytes) {
            std::ofstream out(context, std::ios::binary | std::ios::trunc);
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        };
        writeContext(minimal);
        const auto minimalLoaded = mintfixed::Load(exe);
        CHECK(minimalLoaded.valid);
        CHECK(minimalLoaded.context.generatedUnixMs == 9223372036854775808ULL);

        // Unicode escapes, including surrogate pairs, must be decoded correctly.
        std::string withUnicode = minimal;
        withUnicode.insert(withUnicode.size() - 1, R"(,"extra":"\uD83D\uDE80")");
        writeContext(withUnicode);
        CHECK(mintfixed::Load(exe).valid);

        // Duplicate keys must fail, including keys in otherwise ignored data.
        std::string duplicateKey = minimal;
        duplicateKey.insert(duplicateKey.size() - 1, R"(,"extra":{"x":1,"x":2})");
        writeContext(duplicateKey);
        CHECK(!mintfixed::Load(exe).valid);

        std::string invalidSurrogate = minimal;
        invalidSurrogate.insert(invalidSurrogate.size() - 1, R"(,"extra":"\uD800")");
        writeContext(invalidSurrogate);
        CHECK(!mintfixed::Load(exe).valid);

        std::string decimal = minimal;
        decimal.insert(decimal.size() - 1, R"(,"extra":1.5)");
        writeContext(decimal);
        CHECK(!mintfixed::Load(exe).valid);

        std::string rawNul = minimal;
        rawNul.push_back('\0');
        writeContext(rawNul);
        CHECK(!mintfixed::Load(exe).valid);

        std::string tooDeep = minimal;
        tooDeep.insert(tooDeep.size() - 1, ",\"extra\":" + std::string(26, '[') + "0" + std::string(26, ']'));
        writeContext(tooDeep);
        CHECK(!mintfixed::Load(exe).valid);

        // A missing source archive may have null byte size and mtime.
        writeContext(minimal);
        CHECK(mintfixed::Load(exe).valid);
        auto missingArchive = nlohmann::json::parse(minimal);
        missingArchive["installed_mods"] = nlohmann::json::array({
            {{"name", "Missing"}, {"provider", "file"}, {"integration_order", 0},
             {"archive", {{"path", "missing.pak"}, {"exists", false},
                          {"byte_size", nullptr}, {"modified_unix_ms", nullptr}}},
             {"archive_type", "missing"},
             {"archive_index", {{"status", "unreadable"}, {"paks", nlohmann::json::array()}}}}
        });
        writeContext(missingArchive.dump());
        CHECK(mintfixed::Load(exe).valid);
        missingArchive["installed_mods"][0]["archive"]["exists"] = true;
        writeContext(missingArchive.dump());
        CHECK(!mintfixed::Load(exe).valid); // Existing archive cannot have null byte_size.

        writeContext(minimal);
        CHECK(mintfixed::Load(exe).valid);
        { std::ofstream out(installed, std::ios::binary | std::ios::app); out << "changed"; }
        const auto changed = mintfixed::Load(exe);
        CHECK(!changed.valid && changed.stale);
        CHECK(changed.error.find("mods_P.pak") != std::string::npos);
        const fs::path staleReport = temp / "stale-crash.txt";
        {
            std::ofstream out(staleReport);
            out << "assert  : Failed to find function ChangeColorOfDot in HUD_CroNewGrenadeLauncher_C\n";
        }
        CHECK(triage::AppendTo(staleReport, exe, {}));
        std::ifstream staleInput(staleReport);
        const std::string staleText((std::istreambuf_iterator<char>(staleInput)),
                                    std::istreambuf_iterator<char>());
        CHECK(staleText.find("status                  : stale_context") != std::string::npos);
        CHECK(staleText.find("class.candidates") == std::string::npos);
        CHECK(staleText.find("Nested PAK") == std::string::npos);
        // Correct size but wrong mtime must also be rejected.
        auto wrongTime = nlohmann::json::parse(stampInstalledPak(minimal));
        wrongTime["installed_pak"]["modified_unix_ms"] =
            wrongTime["installed_pak"]["modified_unix_ms"].get<std::uint64_t>() + 10000;
        writeContext(wrongTime.dump());
        CHECK(mintfixed::Load(exe).stale);
        writeContext(stampInstalledPak(minimal));
        CHECK(mintfixed::Load(exe).valid);
        fs::remove(installed);
        CHECK(mintfixed::Load(exe).stale); // Uninstall / missing merged PAK.

        std::printf("mintfixed context ok\n");
    } catch (const std::exception& ex) {
        std::printf("mintfixed context selftest error: %s\n", ex.what());
        CHECK(false);
    }
}
}

namespace {
void TestBlueprintRefs() {
    const std::string fatal =
        "assert  : Failed to find function Try Set Lit in PRJ_GrenadeLauncher_C /Game/Maps/SpaceRig\n"
        "#0  /Game/WeaponsNTools/GrenadeLauncher/WPN_GrenadeLauncher.WPN_GrenadeLauncher_C:ExecuteUbergraph\n";
    const auto parsed = blueprint::ParseFailure(fatal, "fsd");
    CHECK(parsed.functionName == "Try Set Lit");
    CHECK(parsed.targetClass == "PRJ_GrenadeLauncher_C");
    CHECK(parsed.callerPackage == "fsd/content/weaponsntools/grenadelauncher/wpn_grenadelauncher");
    CHECK(shared::PackageKey("/Game/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher.PRJ_GrenadeLauncher_C:OnImpact", "fsd") ==
          shared::PackageKey("../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher.uasset", "fsd"));
    CHECK(shared::PackageKey("/Engine/Transient.GameEngine_123", "fsd") == "engine/content/transient");
    CHECK(shared::PackageKey("../../../FSD/Content/Maps/Game/LVL_Inside.umap", "fsd") ==
          "fsd/content/maps/game/lvl_inside");
    CHECK(shared::PackageKey("../../../FSD/Content/Maps/Engine/LVL_Inside.uasset", "fsd") ==
          "fsd/content/maps/engine/lvl_inside");
    CHECK(shared::PackageKey("OtherFSD/Content/Maps/Level.uasset", "fsd").empty());
    CHECK(shared::PackageKey("/Game/Maps/Game/LVL_Inside.LVL_Inside_C:Call", "fsd") ==
          "fsd/content/maps/game/lvl_inside");
    // The vanilla PAK must be derived from the project name, not hard-coded to FSD.
    const auto otherGame = std::filesystem::path("C:/Games/OtherProject/Binaries/Win64/Game.exe");
    const auto vanilla = shared::VanillaPakPath(otherGame);
    CHECK(vanilla.filename() == "OtherProject-WindowsNoEditor.pak");
    CHECK(vanilla.parent_path().filename() == "Paks");
    CHECK(vanilla.parent_path().parent_path().filename() == "Content");
    CHECK(shared::VanillaPakPath("C:/Games/OtherProject/Invalid/Game.exe").empty());
    CHECK(blueprint::ParseFailure("#0  /Game/A/B\n", "fsd").functionName.empty());
    const auto paths = blueprint::ClassPathCandidates({
        "../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher.uasset",
        "../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher.uexp",
        "../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher_OLD.uasset"},
        parsed.targetClass, "fsd");
    CHECK(paths.size() == 1);
    CHECK(paths[0] == "fsd/content/weaponsntools/grenadelauncher/prj_grenadelauncher");
    std::printf("blueprint refs ok\n");
}
}

int main()
{
    TestBlueprintRefs();
    TestNames();
    TestPattern();
    TestBytecode();
    TestSymbols();
    TestSections();
    TestTriage();
    TestMintfixedContext();
    if (g_fails) { std::printf("%d CHECK(s) FAILED\n", g_fails); return 1; }
    std::printf("all ok\n");
    return 0;
}
