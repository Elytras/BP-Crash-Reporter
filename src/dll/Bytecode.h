#pragma once
/*
Bytecode.h

Names the instruction the VM was about to execute, for the offset line of each Blueprint frame in
the report.

There is no full Kismet disassembler here, and none is needed. A disassembler exists to render a
whole function from offset 0, because bytecode is variable-length and not self-synchronising and
you therefore cannot decode from an arbitrary offset. At crash time we are not at an arbitrary
offset: `FFrame::Code` is the VM's instruction pointer and so always sits on an instruction
boundary, and one byte read tells us which node failed.

  Limitation: opcode name and callee name only, no operand rendering, so a report says
  "EX_FinalFunction -> Foo" rather than the argument expressions. If a dump ever leaves you
  guessing, add the recursive operand skip table and render the function from offset 0.
*/

#include <cstdint>
#include <cstdio>

#include "NamePool.h"
#include "Platform.h"
#include "Ue.h"

namespace bpc::bytecode
{
    inline const char* OpName(uint8_t op)
    {
        switch (op)
        {
        case 0x00: return "EX_LocalVariable";
        case 0x01: return "EX_InstanceVariable";
        case 0x02: return "EX_DefaultVariable";
        case 0x04: return "EX_Return";
        case 0x06: return "EX_Jump";
        case 0x07: return "EX_JumpIfNot";
        case 0x09: return "EX_Assert";
        case 0x0B: return "EX_Nothing";
        case 0x0F: return "EX_Let";
        case 0x12: return "EX_ClassContext";
        case 0x13: return "EX_MetaCast";
        case 0x14: return "EX_LetBool";
        case 0x15: return "EX_EndParmValue";
        case 0x16: return "EX_EndFunctionParms";
        case 0x17: return "EX_Self";
        case 0x18: return "EX_Skip";
        case 0x19: return "EX_Context";
        case 0x1A: return "EX_Context_FailSilent";
        case 0x1B: return "EX_VirtualFunction";
        case 0x1C: return "EX_FinalFunction";
        case 0x1D: return "EX_IntConst";
        case 0x1E: return "EX_FloatConst";
        case 0x1F: return "EX_StringConst";
        case 0x20: return "EX_ObjectConst";
        case 0x21: return "EX_NameConst";
        case 0x22: return "EX_RotationConst";
        case 0x23: return "EX_VectorConst";
        case 0x24: return "EX_ByteConst";
        case 0x25: return "EX_IntZero";
        case 0x26: return "EX_IntOne";
        case 0x27: return "EX_True";
        case 0x28: return "EX_False";
        case 0x29: return "EX_TextConst";
        case 0x2A: return "EX_NoObject";
        case 0x2B: return "EX_TransformConst";
        case 0x2C: return "EX_IntConstByte";
        case 0x2D: return "EX_NoInterface";
        case 0x2E: return "EX_DynamicCast";
        case 0x2F: return "EX_StructConst";
        case 0x30: return "EX_EndStructConst";
        case 0x31: return "EX_SetArray";
        case 0x32: return "EX_EndArray";
        case 0x33: return "EX_PropertyConst";
        case 0x34: return "EX_UnicodeStringConst";
        case 0x35: return "EX_Int64Const";
        case 0x36: return "EX_UInt64Const";
        case 0x38: return "EX_PrimitiveCast";
        case 0x39: return "EX_SetSet";
        case 0x3A: return "EX_EndSet";
        case 0x3B: return "EX_SetMap";
        case 0x3C: return "EX_EndMap";
        case 0x3D: return "EX_SetConst";
        case 0x3E: return "EX_EndSetConst";
        case 0x3F: return "EX_MapConst";
        case 0x40: return "EX_EndMapConst";
        case 0x42: return "EX_StructMemberContext";
        case 0x43: return "EX_LetMulticastDelegate";
        case 0x44: return "EX_LetDelegate";
        case 0x45: return "EX_LocalVirtualFunction";
        case 0x46: return "EX_LocalFinalFunction";
        case 0x48: return "EX_LocalOutVariable";
        case 0x4A: return "EX_DeprecatedOp4A";
        case 0x4B: return "EX_InstanceDelegate";
        case 0x4C: return "EX_PushExecutionFlow";
        case 0x4D: return "EX_PopExecutionFlow";
        case 0x4E: return "EX_ComputedJump";
        case 0x4F: return "EX_PopExecutionFlowIfNot";
        case 0x50: return "EX_Breakpoint";
        case 0x51: return "EX_InterfaceContext";
        case 0x52: return "EX_ObjToInterfaceCast";
        case 0x53: return "EX_EndOfScript";
        case 0x54: return "EX_CrossInterfaceCast";
        case 0x55: return "EX_InterfaceToObjCast";
        case 0x5A: return "EX_WireTracepoint";
        case 0x5B: return "EX_SkipOffsetConst";
        case 0x5C: return "EX_AddMulticastDelegate";
        case 0x5D: return "EX_ClearMulticastDelegate";
        case 0x5E: return "EX_Tracepoint";
        case 0x5F: return "EX_LetObj";
        case 0x60: return "EX_LetWeakObjPtr";
        case 0x61: return "EX_BindDelegate";
        case 0x62: return "EX_RemoveMulticastDelegate";
        case 0x63: return "EX_CallMulticastDelegate";
        case 0x64: return "EX_LetValueOnPersistentFrame";
        case 0x65: return "EX_ArrayConst";
        case 0x66: return "EX_EndArrayConst";
        case 0x67: return "EX_SoftObjectConst";
        case 0x68: return "EX_CallMath";
        case 0x69: return "EX_SwitchValue";
        case 0x6A: return "EX_InstrumentationEvent";
        case 0x6B: return "EX_ArrayGetByRef";
        case 0x6C: return "EX_ClassSparseDataVariable";
        case 0x6D: return "EX_FieldPathConst";
        default:   return "EX_?";
        }
    }

    /*
    Describe the instruction at `code` into `out`. Every read is protection-checked first, so a
    torn or bogus Code pointer degrades to a short string rather than faulting inside the handler.
    */
    inline void Describe(const uint8_t* code, char* out, size_t cap)
    {
        if (plat::BadRead(code, 1)) { ::strncpy_s(out, cap, "<code?>", _TRUNCATE); return; }

        const uint8_t op = *code;
        const char* name = OpName(op);
        char callee[256] = {};

        switch (op)
        {
        // Direct UFunction pointer operand.
        case 0x1C: case 0x46: case 0x68:
            if (!plat::BadRead(code + 1, 8))
            {
                auto* fn = *reinterpret_cast<ue::UObject* const*>(code + 1);
                if (!plat::BadRead(fn, sizeof(ue::UObject))) names::Of(fn, callee, sizeof(callee));
            }
            break;

        // FName operand. This assumes the 8-byte shipping FName; a case-preserving build stores
        // 12 bytes and the name renders as <name?>, which is a cosmetic loss rather than a fault.
        case 0x1B: case 0x45:
            if (!plat::BadRead(code + 1, 8))
                names::Decode(*reinterpret_cast<const ue::FName*>(code + 1), callee, sizeof(callee));
            break;

        case 0x20:   // EX_ObjectConst
            if (!plat::BadRead(code + 1, 8))
            {
                auto* o = *reinterpret_cast<ue::UObject* const*>(code + 1);
                if (!plat::BadRead(o, sizeof(ue::UObject))) names::Of(o, callee, sizeof(callee));
            }
            break;

        default: break;
        }

        if (callee[0]) ::sprintf_s(out, cap, "%s -> %s", name, callee);
        else           ::sprintf_s(out, cap, "%s", name);
    }
}
