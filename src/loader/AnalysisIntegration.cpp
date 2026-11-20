#include "Triage.h"
#include "AssetAnalysis.h"

// Keep all post-exit analysis inside bpcrash.exe. Preserve upstream Triage.h's
// external API; the patch renames only the original implementation functions.
namespace bpc::triage {
fs::path AppendToReportRaw(unsigned long pid, const fs::path& dir,
                           const fs::path& gameExe,
                           const std::vector<fs::path>& extraPaks);
bool AppendToRaw(const fs::path& report, const fs::path& gameExe,
                 const std::vector<fs::path>& extraPaks);

fs::path AppendToReport(unsigned long pid, const fs::path& dir,
                        const fs::path& gameExe,
                        const std::vector<fs::path>& extraPaks) {
    const auto report = AppendToReportRaw(pid, dir, gameExe, extraPaks);
    if (!report.empty()) (void)bpc::analysis::AppendTo(report, gameExe, extraPaks);
    return report;
}

bool AppendTo(const fs::path& report, const fs::path& gameExe,
              const std::vector<fs::path>& extraPaks) {
    const bool triaged = AppendToRaw(report, gameExe, extraPaks);
    (void)bpc::analysis::AppendTo(report, gameExe, extraPaks);
    return triaged;
}
} // namespace bpc::triage
