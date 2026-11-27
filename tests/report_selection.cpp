#include "../src/loader/ReportSelection.h"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <stdexcept>

namespace fs = std::filesystem;

int main()
{
    try
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto dir = fs::temp_directory_path() / ("bpcrash-selection-" + std::to_string(nonce));
        if (!fs::create_directory(dir)) throw std::runtime_error("could not create fixture directory");
        struct Cleanup { fs::path dir; ~Cleanup() { std::error_code ec; fs::remove_all(dir, ec); } } cleanup{dir};
        const auto since = fs::file_time_type::clock::now() - std::chrono::seconds(30);
        const auto write = [&](const char* name, const char* reason, bool fatal, bool stale = false)
        {
            const auto path = dir / name;
            {
                std::ofstream out(path);
                out << "=== BPCrashHandler report ===\nreason  : " << reason << '\n';
                if (fatal) out << "assert  : fixture assertion\n";
                if (!out) throw std::runtime_error("could not write fixture");
            }
            fs::last_write_time(path, since + std::chrono::seconds(stale ? -10 : 10));
        };
        const auto expect = [&](std::optional<fs::file_time_type> cutoff, const char* expected)
        {
            std::error_code ec;
            const auto path = bpc::reports::Select(dir, "12345", cutoff, ec);
            if (ec || path.filename() != expected)
                throw std::runtime_error("unexpected selected report: " + path.string() + ", expected: " + expected);
        };
        write("bpcrash_20261127_110000_99999_99_t1.txt", "first-chance exception #99", true);
        write("bpcrash_20261127_110000_12345_98_t1.txt", "startup self-test", true);
        write("bpcrash_20261127_110000_12345_97_t1.txt", "first-chance exception #97", true, true);
        write("bpcrash_20261127_110000_12345_96_t1.txt.bak", "first-chance exception #96", true);
        write("bpcrash_20261127_110000_12345_18446744073709551616_t1.txt", "first-chance exception", true);
        expect(since, "");
        write("bpcrash_20261127_110000_12345_02_t1.txt", "first-chance exception #2", false);
        write("bpcrash_20261127_110000_12345_10_t1.txt", "first-chance exception #10", false);
        expect(since, "bpcrash_20261127_110000_12345_10_t1.txt");
        write("bpcrash_20261127_110000_12345_03_t1.txt", "first-chance exception #3", true);
        expect(since, "bpcrash_20261127_110000_12345_03_t1.txt");
        write("bpcrash_20261127_110000_12345_04_t1.txt", "first-chance exception #4", true);
        expect(since, "bpcrash_20261127_110000_12345_04_t1.txt");
        expect(std::nullopt, "bpcrash_20261127_110000_12345_97_t1.txt");
        std::error_code ec;
        if (!bpc::reports::Select(dir / "missing", "12345", since, ec).empty() || !ec)
            throw std::runtime_error("missing directory was not rejected");
        std::puts("report selection ok");
        return 0;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "report selection failed: %s\n", e.what());
        return 1;
    }
}
