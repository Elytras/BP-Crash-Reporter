# BPCrashHandler

A Blueprint crash-stack tracer for shipping Unreal Engine 4 games. Drop two files next to each
other, run the exe, and play. When the game crashes you get a text file naming the Blueprint
function, the bytecode offset, the node it was about to execute, and the locals and arguments of
each frame, along with the native C++ context of the fault itself.

There is no CLI, no overlay, no per-game rebuild and no generated SDK.

## Use

```
bpcrash.exe
bpcrash.cfg     ->  process = FSD-Win64-Shipping.exe
```

Run `bpcrash.exe`. It stages its embedded DLL beside itself as `bpcrash_live.dll`, then watches for
the process and injects into it. Reports land in that same folder, named
`bpcrash_<date>_<time>_<pid>_<seq>_t<tid>.txt`.

It keeps watching after that, so restarting the game re-injects without restarting the loader. Each
process gets one attempt. Leave the window open for as long as you are playing, and close it or hit
Ctrl+C when you are done.

The injected file is a separate copy on purpose. LoadLibrary holds it locked for as long as the game
runs, so injecting the build output directly would make the next compile fail until you close the
game.

Two files ship, and one of them is a text file with a single setting in it. The DLL travels inside
the exe as a resource and both binaries link the CRT statically, so there is no redist to install
and nothing else to copy.

`bpcrash_status.txt` records each startup phase as it completes, so you can answer "nothing
happened" without a debugger:

```
02:14:34  loaded
02:14:34  crash handler armed
02:14:35  symbols: ready -- main module: PDB (loaded by explicit path)
02:14:35  waiting for the engine (attempt 1, 0 objects)
02:14:54  endpoint resolved
02:14:54  name pool bound
02:14:54  blueprint hooks installed
02:14:55  self-test report written -- startup complete
```

The handler is armed *first*, before symbols and before the engine is resolved, so a crash during
startup still produces a report.

There is no deadline on the engine wait. A cold shader cache or a long intro can put minutes
between injection and the first object, and a timeout cannot tell that apart from a scan that is
simply broken on your build, so the wait retries (backing off to one attempt every five seconds)
and reports progress instead of giving up. It stops early only on a verdict it can prove: the
object array is up and well populated, and `ProcessInternal` still will not resolve after a
sustained minute of that. Injected into a process with no engine in it at all -- the wrong exe, or
`tests/hostload.exe` -- it therefore waits forever and the last three lines never appear. The
load-time report is written *before* the wait as well as after it, so that case still leaves an
artifact on disk saying how far startup got.

A report is also written at load time, whether or not anything went wrong. Its header carries the
self-test for each of the five resolutions, so you can see what the tool found. For example:

```
--- endpoint self-test ---
  [+] GObjects         +0x76B2A80 (chunked, 214883 objects, item stride 24)
  [+] FNamePool        +0x76A1C00
  [+] ProcessEvent     +0x1A4C210 (vtable index 68)
  [+] ProcessInternal  +0x1A51E90
  [+] ProcessLocal     +0x1A4F0C0
```

## Pointing it at another game

Change the one line in `bpcrash.cfg`.

Every address the tool uses comes from `src/dll/Endpoint.h` and nowhere else, and each is found
generically by a layout probe, a pattern, or a vtable walk, rather than from a per-game offset
table. The struct offsets in `src/dll/Ue.h` are fixed by the engine version rather than by the
game, so they hold across titles built on the same UE4 generation.

If a game does break it, the self-test names which of the five resolutions failed.

## What you get

**Native context.** Exception code, faulting address and access kind, RIP with module RVA, the 16
bytes at RIP, ten of the general-purpose registers (`rsp`, `rbp`, `rax`, `rcx`, `rdx`, `r8`, `r9`,
`rbx`, `rsi`, `rdi`), and up to 48 raw stack slots that point into the main module. Written and
flushed before anything that could itself fault.

**Blueprint stack.** For each frame: the full object path, `self`, the bytecode offset within the
function, the opcode about to execute (with the callee's name for a call), and up to 64 locals and
arguments rendered by type. That covers ints, floats, bools, names, strings, object references with
class and name, arrays with their contents, and four common structs (`FVector`, `FRotator`,
`FVector2D`, `FLinearColor`).

## Symbols

The games ship no PDBs, but generated ones sit next to the exes; binfold writes a guessed-name PDB
from a matched function database. Drop `<GameName>.pdb` beside `<GameName>.exe` and it is picked up.

Two settings make that work:

- **`SYMOPT_LOAD_ANYTHING`.** A shipping exe records a CodeView signature for the PDB it was built
  with, and a generated PDB does not match it. Without this flag dbghelp rejects the file on that
  mismatch.
- **An explicit `SymLoadModuleExW` with the `.pdb` as the image name.** The module is unloaded and
  reloaded by path rather than left to dbghelp's own lookup. The startup line reports whether that
  worked (`PDB (loaded by explicit path)`) and what dbghelp ended up with for the main module, so
  you can tell a loaded PDB from a silently absent one.

The search path is set explicitly to the exe's directory plus the DLL's, and does *not* inherit
`_NT_SYMBOL_PATH`, which usually names a symbol server; a network fetch inside a crash handler is
not acceptable. Set `BPCRASH_SYMBOLS=0` to switch the whole thing off.

Symbolication covers **every loaded module**, not just the game:

```
--- faulting instruction ---
FSD-Win64-Shipping.exe!UPlayerCharacter::Tick+0x1A4

--- native call stack (probable return addresses, any module) ---
   0  FSD-Win64-Shipping.exe!UObject::ProcessInternal+0x2C1
   1  UE4SS.dll!LuaMod::on_update+0x88
   2  bpcrash.dll!bpc::interceptor::HookProcessInternal+0x41
```

No unwind data is involved or trusted, since RBP is often already garbage by the time you care.
Instead the stack is scanned for values that sit in executable memory *and* have a call instruction
decoded immediately before them, and the first 40 matches are printed. That filter is what makes the
list readable; without it every vtable pointer, string literal and stale frame the thread ever had
shows up too. The raw-RVA line in the native context above survives as a fallback, in case
symbolication itself dies.

When another injected DLL is on the stack, its frames get named out of its own PDB. The report also
carries a full module table, and the endpoint self-test names what each resolution landed on, which
is how you tell a found address from the correct one:

```
  [+] ProcessInternal  +0x1A51E90  == FSD-Win64-Shipping.exe!UObject::ProcessInternal
```

dbghelp allocates, so it is initialised at load and the main module's PDB is forced resident then,
which keeps symbol parsing off the crash path. It is loaded explicitly from System32, because UE
game folders do sometimes ship their own `dbghelp.dll`. All of it is optional: with no symbols
anywhere, every address falls back to `module+RVA`.

## Antivirus

This will get flagged, and the heuristics are not wrong. The tool waits for a process, opens it,
writes into its address space, starts a remote thread and detours functions, which is the same
sequence a malicious loader runs. No amount of code change makes it look otherwise.

What is done about it here is ordinary hygiene rather than evasion:

- **A version resource on both binaries.** Company and product strings are cheap to fill in, and
  their absence is a common input to reputation heuristics.
- **No packing, no obfuscation, no encrypted payload.** The embedded DLL is stored plainly.
- **`-DBPC_EMBED_DLL=OFF`** ships the DLL as a separate file. A PE that carries another PE in its
  resources, drops it to disk and loads it into a third process has the shape of a dropper, and
  this removes that signal at the cost of one extra file.

None of it is a substitute for an Authenticode certificate. Failing that, add an exclusion for the
folder and send a false-positive report to whichever vendor is blocking you.

## Known limits

- **Native functions called from bytecode do not get their own frame.** The VM calls their
  `ExecFunction` directly, bypassing both hooks. The scripted frame that called them is present,
  with a bytecode offset pointing at the call. A native function entered through *ProcessEvent*,
  such as an RPC, an event, or a manual `call` from a tool, does get a frame, tagged
  `native call via ProcessEvent`. It has no VM frame and so no locals and no bytecode offset, but
  its arguments are printed from ProcessEvent's parameter block, tagged `in` / `out` / `in/out` /
  `ret`.
- **A stack overflow reports fully only on a thread that has run Blueprint.** The handler runs
  on the faulting thread, which by definition has almost no stack left, so the interceptor asks
  for a 64 KB cushion (`SetThreadStackGuarantee`) the first time it sees a thread call into the
  VM. With it the report is complete; without it -- a thread that overflowed having never run a
  UFunction -- the native context, registers and raw stack still land on disk and the rest of
  the passes are lost. The recorder also keeps the outermost 256 frames, so a runaway recursion
  is missing the frames it actually died in; the report says so, and the repeating cycle is
  visible in what survived. `tests/hostload.exe <dll> --overflow [--vm]` reproduces both
  cases.
- **One opcode, not a full disassembly.** `FFrame::Code` is the VM's instruction pointer, so the
  opcode at the crash is read directly. The operands are not decoded, so a call reads
  `EX_FinalFunction -> Foo` without its argument expressions.
- **Rendering stops at fixed depths.** Enums print numerically, nested structs go one level deep and
  show their first 6 members, arrays show their first 8 elements, and each frame prints at most 64
  properties.
- **`FText` payloads are not decoded.** The value renders as `<FText>`, because the concrete
  `ITextData` subclass behind the shared pointer is unknown and there is no offset that can be read
  from it safely.
- **UE4 only, and specifically the UE4.23+ `FNamePool` and the UE4.25+ `FField`/`FProperty` split.**
  The offsets in `Ue.h` were checked against UE4.27. A UE5 build keeps `FName` unchanged but packs
  `FFieldVariant` into 8 bytes, which shifts every `FProperty` field down by 8, and widens `FVector`
  and `FRotator` to doubles. The offsets here do not apply to it.
- **Symbol names are only as good as the PDB.** Generated PDBs carry public symbols with gaps, so
  dbghelp attributes an address to whatever symbol precedes it. Past a plausible function size the
  report leads with `module+RVA` and demotes the name to `(nearest: …)`, rather than asserting
  something like `CheatGodMode_Implementation+0x1B13` as fact.

## Build

```bash
cmake -B build -A x64 && cmake --build build --config Release
```

MinHook is fetched by CMake, and there is nothing else to install.

Windows x64 only, and CMake says so rather than letting you find out through missing headers. The
resolution layer's contact with the OS is behind one API -- `src/dll/Platform.h`, six functions,
implemented in `src/dll/Platform_Win32.cpp` -- so that part of a port is small, and
`src/dll/Platform_Posix.cpp` marks the seam. The rest is not abstracted and is not close: the
handler is a vectored exception handler, the symbol layer is dbghelp, the interceptor is MinHook
detouring x86-64 prologues, and the loader injects with `CreateRemoteThread`.

The `selftest` target covers the hand-rolled decoders (pattern scanner, FName pool, opcode table)
and the dbghelp path, without needing a game:

```bash
cmake --build build --config Release --target selftest && build/Release/selftest.exe
```

## Credits and license

MIT, see [LICENSE](LICENSE).

- [MinHook](https://github.com/TsudaKageyu/minhook) (MIT), the only dependency, fetched by CMake.
- [Dumper-7](https://github.com/Encryqed/Dumper-7). The generic FNamePool, GObjects and
  ProcessEvent resolution techniques in `src/dll/Endpoint.cpp` are cut-down ports of its scanners.
