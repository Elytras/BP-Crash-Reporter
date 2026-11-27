# Mintfixed post-exit integration (local development)

The existing two-argument watcher behavior is unchanged. A new finite mode is
available for a native Steam launch wrapper that has already waited for DRG:

```
bpcrash-watch --triage-only <session-file> <triage-exe> <Proton command...>
```

The session file is created before launching the game and populated by the
game-side integration with three UTF-8 lines:

1. Wine/Windows PID (decimal).
2. Absolute Windows game executable path.
3. Absolute Windows report directory (the same directory as the session file
   as seen from Linux).

The caller must supply both views of the same report directory; the watcher
cannot verify Wine drive mappings and does not assume any directory name.
Two-line records from the experimental implementation are rejected; update the
producer and watcher together. The shared selector used by both the Windows
loader and native watcher prefers the latest first-chance report carrying a
fatal assertion. Otherwise it selects the latest first-chance report. The
native watcher additionally requires the report to be at least as recent as
the session marker. Startup self-tests are ignored. It invokes the supplied Proton command with the triage
executable, `--triage`, report path and game path. It never injects and exits
when the child exits. The caller owns the marker and process lifecycle, including a timeout.

The optional v2 manifest `installed_pak.relative_path` supports the fixed
`Content/Paks/mods_P.pak` locator when the source path is POSIX absolute. The
actual game-relative PAK must still match exact size and millisecond mtime.
This is metadata validation, not cryptographic proof of installation identity.
Windows manifests without the field keep the existing identity check.

Build the native watcher with `g++ -O2 -std=c++20 -o bpcrash-watch linux/bpcrash-watch.cpp`.
Build the Windows triage executable using the normal CMake release build; copy
it as `bpcrash-triage.exe` beside the existing verified injection executable.

The portable selector regression tests can be run without Wine or a game:

```
g++ -std=c++20 -Wall -Wextra -Werror tests/report_selection.cpp -o report-selection-test
./report-selection-test
```

The Windows CMake build also provides `report_selection_test.exe`.
