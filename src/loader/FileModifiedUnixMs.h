#pragma once

// std::filesystem::file_time_type is not guaranteed to provide to_sys() in
// every supported MSVC STL version. Read Windows' exact file timestamp instead.
// Rust's SystemTime::duration_since(UNIX_EPOCH).as_millis() uses the same
// millisecond truncation after converting the Windows FILETIME epoch.
#include <cstdint>
#include <filesystem>
#include <optional>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bpc::mintfixed {

inline std::optional<std::uint64_t> FileModifiedUnixMs(const std::filesystem::path& path) {
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return std::nullopt;

    const std::uint64_t ticks =
        (static_cast<std::uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
        static_cast<std::uint64_t>(info.ftLastWriteTime.dwLowDateTime);
    constexpr std::uint64_t kUnixEpochFiletimeTicks = 116444736000000000ULL;
    constexpr std::uint64_t kFiletimeTicksPerMs = 10000ULL;
    if (ticks < kUnixEpochFiletimeTicks) return std::nullopt;
    return (ticks - kUnixEpochFiletimeTicks) / kFiletimeTicksPerMs;
}

} // namespace bpc::mintfixed
