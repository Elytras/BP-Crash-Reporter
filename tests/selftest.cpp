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
#include "../src/loader/BlueprintRefs.h"

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

        // Any address inside a loaded module must resolve at least to module+RVA.
        const void* here = reinterpret_cast<const void*>(&TestSymbols);
        CHECK(sym::Resolve(here, out, sizeof(out)));
        CHECK(::strstr(out, "selftest.exe") != nullptr);
        std::printf("  self  : %s\n", out);

        const void* sleepFn = plat::ImportedFunction(L"kernel32.dll", "Sleep");
        CHECK(sym::Resolve(sleepFn, out, sizeof(out)));
        CHECK(::_strnicmp(out, "kernel32", 8) == 0);
        std::printf("  export: %s\n", out);

        // This exe ships its own PDB, so we expect a real name here, not just module+RVA.
        if (ready)
        {
            sym::Resolve(here, out, sizeof(out));
            CHECK(::strchr(out, '!') != nullptr || ::strstr(out, " (nearest: ") != nullptr);   // 0x21 = '!', the module/symbol separator
        }
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
    const fs::path fixture = fs::path(BPC_SELFTEST_FIXTURES);
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path temp = fs::temp_directory_path() / ("bpcrash-mintfixed-selftest-" + std::to_string(unique));
    struct Cleanup { fs::path path; ~Cleanup() { std::error_code ec; fs::remove_all(path, ec); } } cleanup{temp};
    try {
        const fs::path bin = temp / "FSD" / "Binaries" / "Win64";
        const fs::path paks = temp / "FSD" / "Content" / "Paks";
        fs::create_directories(bin / "mintfixed-bpcrash");
        fs::create_directories(paks);
        const fs::path exe = bin / "FSD-Win64-Shipping.exe";
        { std::ofstream file(exe); file << "dummy"; }
        const fs::path local = temp / "local.pak";
        const fs::path blob = temp / "extensionless-blob";
        fs::copy_file(fixture / "mintfixed_sample.pak", local);
        // Synthetic name-table strings outside the test PAK index. PAK metadata
        // remains readable; this tests the scanner without needing the game.
        { std::ofstream stream(local, std::ios::binary | std::ios::app);
          const std::string marker = "Try Set Lit";
          stream.put('\0'); stream.write(marker.data(), marker.size()); stream.put('\0'); }
        fs::copy_file(fixture / "mintfixed_cache_blob.zip", blob);
        fs::copy_file(local, paks / "mods_P.pak");

        std::size_t seen = 0;
        const auto zip = mintfixed::VisitZipPaks(blob, [&](const std::string& name, const std::vector<unsigned char>& bytes) {
            CHECK(name == "mods/packed.pak");
            CHECK(!bytes.empty());
            CHECK(!triage::PakFilesFromBytes(bytes).empty());
            ++seen;
        });
        CHECK(zip.pakEntries == 1 && zip.decoded == 1 && zip.skipped == 0 && seen == 1);

        const auto jsonEscape = [](const fs::path& path) {
            const auto chars = path.u8string();
            std::string out;
            for (auto c : chars) {
                const char ch = static_cast<char>(c);
                if (ch == '\\' || ch == '"') out.push_back('\\');
                out.push_back(ch);
            }
            return out;
        };
        const fs::path context = bin / "mintfixed-bpcrash" / "crash_context.json";
        {
            std::ofstream out(context);
            out << "{\"schema_version\":1,\"producer\":\"mintfixed\","
                   "\"captured_after_successful_install\":true,\"generated_unix_ms\":100,"
                   "\"installed_pak\":{\"path\":\"" << jsonEscape(paks / "mods_P.pak")
                << "\",\"exists\":true,\"byte_size\":" << fs::file_size(paks / "mods_P.pak") << "},"
                   "\"installed_mods\":["
                   "{\"name\":\"Local Test Mod\",\"provider\":\"file\",\"integration_order\":0,"
                   "\"archive\":{\"path\":\"" << jsonEscape(local) << "\",\"exists\":true,\"byte_size\":"
                << fs::file_size(local) << "},\"archive_type\":\"pak_or_unknown\","
                   "\"nested_paks_must_be_scanned\":false},"
                   "{\"name\":\"Downloaded Test Mod\",\"provider\":\"modio\",\"integration_order\":1,"
                   "\"archive\":{\"path\":\"" << jsonEscape(blob) << "\",\"exists\":true,\"byte_size\":"
                << fs::file_size(blob) << "},\"archive_type\":\"zip\","
                   "\"nested_paks_must_be_scanned\":true,\"modio_reference\":\"https://mod.io/g/drg/m/test\"}] }";
        }
        const auto loaded = mintfixed::Load(exe);
        CHECK(loaded.present && loaded.valid && loaded.context.installedMods.size() == 2);
        const fs::path report = temp / "sample-report.txt";
        {
            std::ofstream out(report);
            out << "assert  : LowLevelFatalError Failed to find function Try Set Lit in WPN_DualMPs_C\n"
                   "#0  /Game/WeaponsNTools/DualMachinePistols/WPN_DualMPs.WPN_DualMPs_C:ExecuteUbergraph\n";
        }
        CHECK(analysis::AppendTo(report, exe, {}));
        CHECK(!analysis::AppendTo(report, exe, {}));
        std::ifstream in(report);
        const std::string result((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(result.find("--- mintfixed mod attribution (bpcrash.exe) ---") != std::string::npos);
        CHECK(result.find("Local Test Mod") != std::string::npos);
        CHECK(result.find("Downloaded Test Mod") != std::string::npos);
        CHECK(result.find("mods/packed.pak") != std::string::npos);
        CHECK(result.find("integration_order: 1") != std::string::npos);
        CHECK(result.find("result.assets_with_sources : 1/1") != std::string::npos);
        CHECK(result.find("scan.paks.total") != std::string::npos);
        CHECK(result.find("scan.nested_zip_paks") != std::string::npos);
        CHECK(result.find("integrity.sha256          : not_revalidated") != std::string::npos);
        CHECK(result.find("--- blueprint function compatibility (mintfixed) ---") != std::string::npos);
        CHECK(result.find("failure.function          : Try Set Lit") != std::string::npos);
        CHECK(result.find("symbols.function.mod_hits : 1") != std::string::npos);
        CHECK(result.find("mod_evidence[1].missing_function    : present") != std::string::npos);
        CHECK(result.find("class[1].evidence          : pak_index_filename") != std::string::npos);
        CHECK(result.find("verification.causation    : not_established") != std::string::npos);

        { std::ofstream out(context); out << "{\"schema_version\":2,\"producer\":\"mintfixed\"}"; }
        CHECK(!mintfixed::Load(exe).valid);
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
    CHECK(blueprint::ParseFailure("#0  /Game/A/B\n", "fsd").functionName.empty());
    const auto paths = blueprint::ClassPathCandidates({
        "../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher.uasset",
        "../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher.uexp",
        "../../../FSD/Content/WeaponsNTools/GrenadeLauncher/PRJ_GrenadeLauncher_OLD.uasset"},
        parsed.targetClass, "fsd");
    CHECK(paths.size() == 1);
    CHECK(paths[0] == "fsd/content/weaponsntools/grenadelauncher/prj_grenadelauncher");
    std::vector<unsigned char> bytes;
    const auto appendWide = [&](const std::string& token) {
        bytes.push_back(0);
        for (auto c : token) { bytes.push_back(static_cast<unsigned char>(c)); bytes.push_back(0); }
        bytes.push_back(0); bytes.push_back(0);
    };
    appendWide("Try Set Lit");
    appendWide("PRJ_GrenadeLauncher_C");
    const auto symbols = blueprint::SearchBytes(bytes, parsed);
    CHECK(symbols.functionName && symbols.className && symbols.complete);
    const std::string nearMiss = "XTry Set LitExtra PRJ_GrenadeLauncher_C_Old";
    const std::vector<unsigned char> falsePositive(nearMiss.begin(), nearMiss.end());
    const auto negative = blueprint::SearchBytes(falsePositive, parsed);
    CHECK(!negative.functionName && !negative.className);
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
