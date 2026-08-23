#pragma once
/*
Ue.h

The UE4 object model as plain structs, with no generated SDK behind it. Every member sits at the
engine's real offset, so reading a field is an ordinary member access rather than a hand-written
`*(T*)((uint8_t*)p + kOff)`. Under the UE4-only scope these offsets are engine constants, not
something that changes per game.

Checked against a Dumper-7 dump of Deep Rock Galactic (UE4.27), in the SDK's Basic.hpp and
CoreUObject_classes.hpp. Two of them are easy to get wrong:

  FProperty::ElementSize is 0x3C, not 0x38 (0x38 is ArrayDim).
  FProperty::Offset      is 0x4C.

What does genuinely change per build is the set of addresses (ProcessEvent, ProcessInternal,
FFrame::Step, GNatives, GObjects, FNamePool), and those come from Endpoint.h instead.
*/

#include <cstddef>
#include <cstdint>

namespace bpc::ue
{
    struct UClass;
    struct UObject;
    struct FField;
    struct FProperty;

    // FName

    // 8 bytes: shipping UE4 builds have neither case-preserving names nor FNAME_OUTLINE_NUMBER.
    struct FName
    {
        int32_t ComparisonIndex;
        int32_t Number;
    };

    // UObject chain

    struct UObject
    {
        void*    VTable;      // 0x00
        int32_t  Flags;       // 0x08  EObjectFlags
        int32_t  Index;       // 0x0C  InternalIndex
        UClass*  Class;       // 0x10
        FName    Name;        // 0x18
        UObject* Outer;       // 0x20
    };

    struct UField : UObject { UField* Next; };                     // 0x28

    struct UStruct : UField
    {
        uint8_t  BaseChain[0x10];   // 0x30  FStructBaseChain
        UStruct* SuperStruct;       // 0x40
        UField*  Children;          // 0x48
        FField*  ChildProperties;   // 0x50
        int32_t  Size;              // 0x58
        int16_t  MinAlignment;      // 0x5C
        uint8_t  Pad5E[0x2];        // 0x5E
        uint8_t* ScriptData;        // 0x60  TArray<uint8> Script { Data, Num, Max }
        int32_t  ScriptNum;         // 0x68
        int32_t  ScriptMax;         // 0x6C
        uint8_t  Pad70[0x40];       // 0x70 .. 0xAF property/ref link chains; UStruct ends at 0xB0
    };

    struct UClass : UStruct
    {
        void*    ClassConstructor;  // 0xB0
        void*    ClassVTableHelper; // 0xB8
        void*    ClassAddRefObjs;   // 0xC0
        uint32_t ClassUnique;       // 0xC8
        uint32_t ClassFlags;        // 0xCC
        uint64_t CastFlags;         // 0xD0  EClassCastFlags
    };

    using FNativeFuncPtr = void (*)(UObject* Context, void* Stack, void* Result);

    struct UFunction : UStruct
    {
        uint32_t       FunctionFlags;  // 0xB0
        uint8_t        PadB4[0x24];    // 0xB4 .. 0xD7
        FNativeFuncPtr ExecFunction;   // 0xD8
    };

    static_assert(sizeof(UObject) == 0x28);
    static_assert(offsetof(UStruct, ChildProperties) == 0x50);
    static_assert(offsetof(UStruct, ScriptData) == 0x60);
    static_assert(offsetof(UClass, CastFlags) == 0xD0);
    static_assert(offsetof(UFunction, FunctionFlags) == 0xB0);
    static_assert(offsetof(UFunction, ExecFunction) == 0xD8);

    // FField / FProperty. UE4.25+ split; no UProperty fork under the UE4-only scope.

    struct FFieldClass
    {
        FName        Name;        // 0x00
        uint64_t     Id;          // 0x08
        uint64_t     CastFlags;   // 0x10  EClassCastFlags, how we identify a property's type
        uint32_t     ClassFlags;  // 0x18
        uint32_t     Pad1C;
        FFieldClass* SuperClass;  // 0x20
    };

    struct FField
    {
        void*        VTable;        // 0x00
        FFieldClass* ClassPrivate;  // 0x08
        void*        OwnerPtr;      // 0x10  FFieldVariant { ptr, bIsUObject }
        bool         OwnerIsUObject;// 0x18
        uint8_t      Pad19[0x7];
        FField*      Next;          // 0x20
        FName        Name;          // 0x28
        int32_t      ObjFlags;      // 0x30
        int32_t      Pad34;
    };

    struct FProperty : FField
    {
        int32_t  ArrayDim;      // 0x38
        int32_t  ElementSize;   // 0x3C   <-- NOT 0x38
        uint64_t PropertyFlags; // 0x40
        uint16_t RepIndex;      // 0x48
        uint8_t  BpRepCond;     // 0x4A
        uint8_t  Pad4B;
        int32_t  Offset;        // 0x4C   Offset_Internal
        FName    RepNotifyFunc; // 0x50
        FProperty* PropertyLinkNext;     // 0x58
        FProperty* NextRef;              // 0x60
        FProperty* DestructorLinkNext;   // 0x68
        FProperty* PostConstructLinkNext;// 0x70  FProperty ends at 0x78
    };

    struct FBoolProperty : FProperty        // 0x78
    {
        uint8_t FieldSize, ByteOffset, ByteMask, FieldMask;
    };
    struct FObjectPropertyBase : FProperty { UClass* PropertyClass; };   // 0x78
    struct FByteProperty       : FProperty { UObject* Enum; };           // 0x78 (UEnum*)
    struct FEnumProperty       : FProperty { FProperty* Underlying; UObject* Enum; };
    struct FStructProperty     : FProperty { UStruct* Struct; };         // 0x78
    struct FArrayProperty      : FProperty { FProperty* Inner; };        // 0x78

    static_assert(offsetof(FProperty, ElementSize) == 0x3C);
    static_assert(offsetof(FProperty, Offset) == 0x4C);
    static_assert(offsetof(FField, Name) == 0x28);
    static_assert(sizeof(FProperty) == 0x78);
    static_assert(offsetof(FBoolProperty, ByteMask) == 0x7A);
    static_assert(offsetof(FStructProperty, Struct) == 0x78);

    // EClassCastFlags. How we ask what kind of property something is, with no SDK in the build.

    enum ECastFlags : uint64_t
    {
        CAST_None = 0,
        CAST_UField = 1ull << 0,
        CAST_FInt8Property = 1ull << 1,
        CAST_UEnum = 1ull << 2,
        CAST_UStruct = 1ull << 3,
        CAST_UScriptStruct = 1ull << 4,
        CAST_UClass = 1ull << 5,
        CAST_FByteProperty = 1ull << 6,
        CAST_FIntProperty = 1ull << 7,
        CAST_FFloatProperty = 1ull << 8,
        CAST_FUInt64Property = 1ull << 9,
        CAST_FClassProperty = 1ull << 10,
        CAST_FUInt32Property = 1ull << 11,
        CAST_FInterfaceProperty = 1ull << 12,
        CAST_FNameProperty = 1ull << 13,
        CAST_FStrProperty = 1ull << 14,
        CAST_FProperty = 1ull << 15,
        CAST_FObjectProperty = 1ull << 16,
        CAST_FBoolProperty = 1ull << 17,
        CAST_FUInt16Property = 1ull << 18,
        CAST_UFunction = 1ull << 19,
        CAST_FStructProperty = 1ull << 20,
        CAST_FArrayProperty = 1ull << 21,
        CAST_FInt64Property = 1ull << 22,
        CAST_FDelegateProperty = 1ull << 23,
        CAST_FNumericProperty = 1ull << 24,
        CAST_FMulticastDelegateProperty = 1ull << 25,
        CAST_FObjectPropertyBase = 1ull << 26,
        CAST_FWeakObjectProperty = 1ull << 27,
        CAST_FLazyObjectProperty = 1ull << 28,
        CAST_FSoftObjectProperty = 1ull << 29,
        CAST_FTextProperty = 1ull << 30,
        CAST_FInt16Property = 1ull << 31,
        CAST_FDoubleProperty = 1ull << 32,
        CAST_FSoftClassProperty = 1ull << 33,
        CAST_FMapProperty = 1ull << 46,
        CAST_FSetProperty = 1ull << 47,
        CAST_FEnumProperty = 1ull << 48,
    };

    inline bool IsA(const FField* f, uint64_t cast)
    {
        return f && f->ClassPrivate && (f->ClassPrivate->CastFlags & cast) != 0;
    }
    inline bool IsA(const UObject* o, uint64_t cast)
    {
        return o && o->Class && (o->Class->CastFlags & cast) != 0;
    }

    // EPropertyFlags. Separates a function's parameters from its true locals.

    enum EPropFlags : uint64_t
    {
        CPF_Parm          = 0x0000000000000080,
        CPF_OutParm       = 0x0000000000000100,
        CPF_ReturnParm    = 0x0000000000000400,
        CPF_ReferenceParm = 0x0000000008000000,
    };

    // EFunctionFlags, the two we use.

    enum EFuncFlags : uint32_t
    {
        FUNC_Native = 0x00000400,
        FUNC_Event  = 0x00000800,
    };

    // EObjectFlags. The validity test below matches the SDK's IsValid().

    enum EObjFlags : int32_t
    {
        RF_ClassDefaultObject = 0x00000010,
        RF_ArchetypeObject    = 0x00000020,
        RF_BeginDestroyed     = 0x00008000,
        RF_FinishDestroyed    = 0x00010000,
    };

    inline bool IsValid(const UObject* o)
    {
        return o && o->Class && !(o->Flags & (RF_BeginDestroyed | RF_FinishDestroyed));
    }

    // FFrame, the live VM frame handed to ProcessInternal.

    struct FFrame
    {
        uint8_t        Pad00[0x10];   // 0x00  FOutputDevice vtable + FFrame base
        UFunction*     Node;          // 0x10
        UObject*       Object;        // 0x18
        const uint8_t* Code;          // 0x20  bytecode instruction pointer
        uint8_t*       Locals;        // 0x28  params + locals buffer
    };

    static_assert(offsetof(FFrame, Code) == 0x20);
    static_assert(offsetof(FFrame, Locals) == 0x28);

    // Container payloads read out of property slots.

    struct FString { wchar_t* Data; int32_t Num; int32_t Max; };      // 16B
    struct FScriptArray { void* Data; int32_t Num; int32_t Max; };    // 16B

    /* FText on UE4 is 24 bytes: TSharedRef<ITextData> (ptr + refctrl ptr) + uint32 flags. We do
       not decode the payload, because the concrete ITextData subclass is unknown and reaching a
       hardcoded offset into it is a documented crash source. It renders as <FText>. */
    struct FText { void* Data; void* RefCtrl; uint32_t Flags; uint32_t Pad; };
    static_assert(sizeof(FText) == 24);

    // Iterates a UStruct's ChildProperties: params and locals, in declaration order.
    struct FieldIter
    {
        FField* f;
        FField* operator*() const { return f; }
        FieldIter& operator++() { f = f ? f->Next : nullptr; return *this; }
        bool operator!=(const FieldIter& o) const { return f != o.f; }
    };
    struct FieldRange
    {
        FField* head;
        explicit FieldRange(const UStruct* s) : head(s ? s->ChildProperties : nullptr) {}
        FieldIter begin() const { return { head }; }
        FieldIter end()   const { return { nullptr }; }
    };
}
