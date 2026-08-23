#pragma once
/*
Endpoint.h

The single source of every address and global the tool uses. No other file may hold a hardcoded
address, an RVA, or a game-specific signature; if one is needed, it belongs here.

Each of these is resolved generically, by pattern, layout probe, or vtable walk, so pointing the
tool at a different UE4 title is a config change and nothing else. There is no per-game table.

  FNamePool         layout-probing scan for the pool constructor       (from Dumper-7)
  GObjects          .data scan validating FChunkedFixedUObjectArray    (from Dumper-7)
  ProcessEvent      UObject vtable walk for the FunctionFlags tests    (from Dumper-7)
  ProcessInternal   ExecFunction of any pure-scripted UFunction        (needs GObjects)
  ProcessLocal      PDB symbol, else the call inside ProcessInternal   (the BP-call funnel)

FFrame::Step and GNatives are absent because Bytecode.h decodes from its own opcode table and
never consults the engine's dispatch table, so resolving them would be dead weight.

Report() is written verbatim into the dump file header, so which resolution moved is answerable
from the report alone, without a debugger or a console.
*/

#include <cstdint>
#include <string>

#include "Ue.h"

namespace bpc::endpoint
{
    struct Resolved
    {
        void*    processEvent    = nullptr;   // UObject::ProcessEvent(UFunction*, void* parms)
        int      processEventIdx = -1;        // its vtable index (diagnostic)
        void*    processInternal = nullptr;   // UObject::ProcessInternal(FFrame&, void* result)

        /* ProcessLocalScriptFunction(UObject*, FFrame&, void*), the bytecode interpreter, and the
           funnel every scripted function body passes through. ProcessInternal only covers
           functions entered from ProcessEvent; a Blueprint calling another Blueprint goes
           execLocalFinalFunction -> CallFunction -> here, never touching ProcessInternal. Hooking
           only ProcessInternal reports a one-frame stack for a call chain twenty deep. */
        void*    processLocal    = nullptr;
        uint8_t* namePool        = nullptr;   // FNamePool / FNameEntryAllocator
        uint8_t* gObjects        = nullptr;   // FUObjectArray
    };

    /*
    Outcome of one resolution attempt.

      NotYet    nothing is wrong; the engine has not built what we need yet. The caller retries.
      Ready     everything mandatory resolved. Hooks can go in.
      Rejected  a PROVABLE failure: the object array is up and well populated, and ProcessInternal
                still will not resolve after sustained retries -- so it is our resolution that is
                broken, not the engine that is slow.

    The distinction is the whole point. A deadline cannot tell "this game takes four minutes to
    reach the main menu" from "this build broke our scan", so it used to give up on the first and
    stay silent about the second.
    */
    enum class Progress { NotYet, Ready, Rejected };

    /*
    One non-blocking resolution attempt. Called in a loop from the DllMain worker; the caller owns
    the pacing so it can log progress and so nothing here ever blocks for minutes. Idempotent once
    Ready -- later calls return Ready without redoing the work.
    */
    Progress TryInit();

    bool            Ready();
    const Resolved& Get();

    // Human-readable per-resolution outcome, one line each. Written into every dump header.
    const std::string& Report();

    // Object array access. This is the only place that knows the array's layout.

    int32_t     NumObjects();
    ue::UObject* ObjectByIndex(int32_t i);
}
