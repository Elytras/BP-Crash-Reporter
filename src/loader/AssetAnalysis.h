#pragma once

#include <filesystem>
#include <vector>

namespace bpc::analysis {
namespace fs = std::filesystem;
// Runs in bpcrash.exe only after DRG has terminated, never inside the crash handler DLL.
// Returns true if a section was appended; false if the report was invalid/already analyzed.
bool AppendTo(const fs::path& report, const fs::path& gameExe,
              const std::vector<fs::path>& extraPaks);
} // namespace bpc::analysis
