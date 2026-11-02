#pragma once
/*
Triage.h

What bpcrash.exe adds to a crash report after the game has exited: for an async-load fatal, the
asset being loaded, the parent it could not find, and the pak files that hold each.

It runs here and not in the DLL because the evidence is not on disk while the game is dying. In
UE4.27's async loader, `FAsyncPackage::EventDrivenIndexToObject` logs a "****DumpDependencies"
block (the export, "Linker is <file>", "Missing Dependency, request for <object>") and returns
null, and `EventDrivenSerializeExport` then raises "Could not find SuperStruct <super> to create
<created>". Those log lines are still in the engine's thread buffer when the DLL's handler runs;
UE flushes them to <Project>/Saved/Logs/<Project>.log only on its own crash path, after it. So the
loader waits for the process to go, then reads the log, which is the same log any UE game writes:
nothing here is per game.
*/

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace bpc::triage
{
    namespace fs = std::filesystem;

    // The last dependency dump in the log.
    struct Dump
    {
        size_t                   line = 0;    // 0-based line of "****DumpDependencies"
        size_t                   after = 0;   // log lines after the block
        std::string              exportPath;  // "/Game/M/Child.Child_C:Fn"
        std::string              linker;      // "../../../FSD/Content/M/Child.uasset"
        std::vector<std::string> missing;     // objects it requested that were not created
    };

    // "Could not find SuperStruct <super> to create <created>" -> true and both names.
    bool FatalNames(std::string_view message, std::string& super, std::string& created);

    bool LastDump(const std::vector<std::string>& lines, Dump& out);

    // Whether `d` is the dump the fatal comes from: its export ends in <created>, a missing object in <super>.
    bool Matches(const Dump& d, std::string_view super, std::string_view created);

    // "/Game/A/B.B_C:Fn" or "../../../<project>/Content/A/B.uasset" -> "/Game/A/B".
    std::string PackageOf(std::string_view path, std::string_view project);

    // Every file in a pak, as "<project>/Content/...", lowercased. Empty if the index is encrypted or unreadable.
    std::vector<std::string> PakFiles(const fs::path& pak);

    // The report section for a crash with this assert message (empty if the crash was not a UE fatal).
    std::string Run(const std::string& assertMessage, const fs::path& gameExe, const std::vector<fs::path>& extraPaks);

    /* The crash report process `pid` left in `dir`, with Run()'s section appended. Returns that report, or an
       empty path when the process wrote no crash report (a clean exit). */
    fs::path AppendToReport(unsigned long pid, const fs::path& dir, const fs::path& gameExe,
                            const std::vector<fs::path>& extraPaks);

    // Append Run()'s section to one given report. The `--triage` command line.
    bool AppendTo(const fs::path& report, const fs::path& gameExe, const std::vector<fs::path>& extraPaks);
}
