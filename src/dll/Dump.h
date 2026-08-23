#pragma once
/*
Dump.h

Writes the crash report. Armed once at load by DllMain, then passive until the process faults.
The report is produced in two passes, in this order:

  1. Native context, allocation-free, written and flushed immediately. Exception code, faulting
     address, RIP + module RVA, the faulting bytes, and a return-address scan of the stack. If
     everything after this dies, this much is already on disk.
  2. Blueprint stack, SEH-guarded per frame. Function path, bytecode offset, the instruction, and
     the typed locals and arguments.

The handler always returns EXCEPTION_CONTINUE_SEARCH, so it observes crashes without swallowing
them and the game still dies the way it was going to.
*/

namespace bpc::dump
{
    // Install the vectored handler. Idempotent.
    void Arm();

    // Write a report right now. Used for the load-time self-test as well as from the handler.
    void WriteNow(const char* reason);

    /*
    Append one startup phase to bpcrash_status.txt, beside the DLL, flushed immediately.

    If something during startup hangs or faults before the handler is armed there is no crash
    report and therefore no evidence at all, so this file answers "how far did it get" without a
    debugger and without a console. Truncated at load, appended to thereafter.
    */
    void Breadcrumb(const char* phase);
}
