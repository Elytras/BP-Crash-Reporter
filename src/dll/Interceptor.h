#pragma once
/*
Interceptor.h

Maintains the live Blueprint call stack that Dump.cpp reads at crash time. Two hooks feed it:

  ProcessEvent    external entry into the VM (native C++ -> Blueprint). Catches the boundary
                  call, including native UFunctions, which never reach ProcessInternal.
  ProcessInternal every scripted UFunction, including BP -> BP calls that never pass through
                  ProcessEvent. This is the hook that produces most of the stack, and the only
                  one with an FFrame, so the only one that can report locals and a bytecode
                  offset.

A scripted function entered from native code hits both hooks. To avoid a duplicate frame,
ProcessEvent only records one when the target is not scripted (`ExecFunction != ProcessInternal`);
otherwise ProcessInternal is about to record a better version of the same frame.

A native UFunction called from bytecode goes through neither hook, because the VM calls its
ExecFunction directly, so it does not get a frame of its own. The scripted frame that called it
does, with a bytecode offset pointing at the call.

The stack is thread-local and fixed-size, so it needs no allocation and no lock, and a crash on
any thread reads only that thread's own frames.
*/

#include <cstdint>

#include "Ue.h"

namespace bpc::interceptor
{
    struct Frame
    {
        ue::UFunction* node  = nullptr;
        ue::UObject*   obj   = nullptr;
        ue::FFrame*    frame = nullptr;   // null for a ProcessEvent frame (no VM frame exists)

        /* ProcessEvent's parameter block. Such a frame has no FFrame and therefore no locals,
           but it does carry the arguments the function was called with. Null on a VM frame,
           where FFrame::Locals already covers the parameters. */
        void*          parms = nullptr;
    };

    /* Fixed depth: frames past this are dropped rather than the buffer grown, so a stack at the
       cap has lost its innermost frames. Dump.cpp reads it to say so in the report. */
    constexpr int kMaxDepth = 256;

    // Current thread's frames, innermost LAST. Valid only on the calling thread.
    const Frame* Stack(int& count);

    bool Install();
    void Uninstall();
}
