
from vstruct.primitives import *
from vstruct import VStruct,VArray

DWORD = v_uint32

class NT_TIB(VStruct):
    _fields_ = [
        ("ExceptionList", v_ptr), # ExceptionRegistration structures.
        ("StackBase", v_ptr),
        ("StackLimit", v_ptr),
        ("SubSystemTib", v_ptr),
        ("FiberData", v_ptr),
        ("Version", v_ptr),
        ("ArbitraryUserPtr", v_ptr),
        ("Self", v_ptr)
    ]

class SEH3_SCOPETABLE(VStruct):
    _fields_ = [
        ("EnclosingLevel", v_int32),
        ("FilterFunction", v_ptr),
        ("HandlerFunction", v_ptr),
    ]

class SEH4_SCOPETABLE(VStruct):
    """
    Much like the SEH3 scopetable with the stack cookie additions
    """
    _fields_ = [
        ("GSCookieOffset", v_int32),
        ("GSCookieXOROffset", v_int32),
        ("EHCookieOffset", v_int32),
        ("EHCookieXOROffset", v_int32),
        ("EnclosingLevel", v_int32),
        ("FilterFunction", v_ptr),
        ("HandlerFunction", v_ptr),
    ]


class CLIENT_ID(VStruct):
    _fields_ = [
        ("UniqueProcess", v_ptr),
        ("UniqueThread", v_ptr)
    ]

class TebReserved32Array(VArray):
    _field_type_ = v_uint32
    _field_count_ = 26

class TebReservedArray(VArray):
    _field_type_ = v_uint32
    _field_count_ = 5

class TEB(VStruct):
    _fields_ = [
        ("TIB", NT_TIB),
        ("EnvironmentPointer", v_ptr),
        ("ClientId", CLIENT_ID),
        ("ActiveRpcHandle", v_ptr),
        ("ThreadLocalStorage", v_ptr),
        ("ProcessEnvironmentBlock", v_ptr),
        ("LastErrorValue", v_uint32),
        ("CountOfOwnedCriticalSections", v_uint32),
        ("CsrClientThread", v_ptr),
        ("Win32ThreadInfo", v_ptr),
        ("User32Reserved", TebReserved32Array),
        ("UserReserved", TebReservedArray),
        ("WOW32Reserved", v_ptr),
        ("CurrentLocale", v_uint32),
        ("FpSoftwareStatusRegister", v_uint32)
        #FIXME not done!
    ]

# Some necessary arrays for the PEB
class TlsExpansionBitsArray(VArray):
    _field_type_ = v_uint32
    _field_count_ = 32
class GdiHandleBufferArray(VArray):
    _field_type_ = v_ptr
    _field_count_ = 34
class TlsBitMapArray(VArray):
    _field_type_ = v_uint32
    _field_count_ = 2

class PEB(VStruct):
    _fields_ = [
        ("InheritedAddressSpace", v_uint8),
        ("ReadImageFileExecOptions", v_uint8),
        ("BeingDebugged", v_uint8),
        ("SpareBool", v_uint8),
        ("Mutant", v_ptr),
        ("ImageBaseAddress", v_ptr),
        ("Ldr", v_ptr),
        ("ProcessParameters", v_ptr),
        ("SubSystemData", v_ptr),
        ("ProcessHeap", v_ptr),
        ("FastPebLock", v_ptr), 
        ("FastPebLockRoutine", v_ptr),
        ("FastPebUnlockRoutine", v_ptr),
        ("EnvironmentUpdateCount", v_uint32),
        ("KernelCallbackTable", v_ptr),
        ("SystemReserved", v_uint32),
        ("AtlThunkSListPtr32", v_ptr),
        ("FreeList", v_ptr),
        ("TlsExpansionCounter", v_uint32),
        ("TlsBitmap", v_ptr),
        ("TlsBitmapBits", TlsBitMapArray),
        ("ReadOnlySharedMemoryBase", v_ptr),
        ("ReadOnlySharedMemoryHeap", v_ptr),
        ("ReadOnlyStaticServerData", v_ptr),
        ("AnsiCodePageData", v_ptr),
        ("OemCodePageData", v_ptr),
        ("UnicodeCaseTableData", v_ptr),
        ("NumberOfProcessors", v_uint32),
        ("NtGlobalFlag", v_uint64),
        ("CriticalSectionTimeout",v_uint64),
        ("HeapSegmentReserve", v_uint32),
        ("HeapSegmentCommit", v_uint32),
        ("HeapDeCommitTotalFreeThreshold", v_uint32),
        ("HeapDeCommitFreeBlockThreshold", v_uint32), 
        ("NumberOfHeaps", v_uint32),
        ("MaximumNumberOfHeaps", v_uint32),
        ("ProcessHeaps", v_ptr),
        ("GdiSharedHandleTable", v_ptr),
        ("ProcessStarterHelper", v_ptr),
        ("GdiDCAttributeList", v_uint32),
        ("LoaderLock", v_ptr),
        ("OSMajorVersion", v_uint32),
        ("OSMinorVersion", v_uint32),
        ("OSBuildNumber", v_uint16),
        ("OSCSDVersion", v_uint16),
        ("OSPlatformId", v_uint32), 
        ("ImageSubsystem", v_uint32),
        ("ImageSubsystemMajorVersion", v_uint32),
        ("ImageSubsystemMinorVersion", v_uint32),
        ("ImageProcessAffinityMask", v_uint32),
        ("GdiHandleBuffer", GdiHandleBufferArray),
        ("PostProcessInitRoutine", v_ptr),
        ("TlsExpansionBitmap", v_ptr),
        ("TlsExpansionBitmapBits", TlsExpansionBitsArray),
        ("SessionId", v_uint32),
        ("AppCompatFlags", v_uint64),
        ("AppCompatFlagsUser", v_uint64),
        ("pShimData", v_ptr),
        ("AppCompatInfo", v_ptr),
        ("CSDVersion", v_ptr), # FIXME make wide char reader?
        ("UNKNOWN", v_uint32),
        ("ActivationContextData", v_ptr),
        ("ProcessAssemblyStorageMap", v_ptr),
        ("SystemDefaultActivationContextData", v_ptr),
        ("SystemAssemblyStorageMap", v_ptr),
        ("MinimumStackCommit", v_uint32),
    ]

class HEAP_ENTRY(VStruct):
    _fields_ = [
        ("Size", v_uint16),
        ("PrevSize", v_uint16),
        ("SegmentIndex", v_uint8),
        ("Flags", v_uint8),
        ("Unused", v_uint8),
        ("TagIndex", v_uint8)
    ]

class ListEntry(VStruct):
    _fields_ = [
        ("Flink", v_ptr),
        ("Blink", v_ptr)
    ]

class HeapSegmentArray(VArray):
    _field_type_ = v_uint32
    _field_count_ = 64
class HeapUnArray(VArray):
    _field_type_ = v_uint8
    _field_count_ = 16
class HeapUn2Array(VArray):
    _field_type_ = v_uint8
    _field_count_ = 2
class HeapFreeListArray(VArray):
    _field_type_ = ListEntry
    _field_count_ = 128

class HEAP(VStruct):
    _fields_ = [
        ("Entry", HEAP_ENTRY),
        ("Signature", v_uint32),
        ("Flags", v_uint32),
        ("ForceFlags", v_uint32),
        ("VirtualMemoryThreshold", v_uint32),
        ("SegmentReserve", v_uint32),
        ("SegmentCommit", v_uint32),
        ("DeCommitFreeBlockThreshold", v_uint32),
        ("DeCommitTotalFreeThreshold", v_uint32),
        ("TotalFreeSize", v_uint32),
        ("MaximumAllocationSize", v_uint32),
        ("ProcessHeapsListIndex", v_uint16),
        ("HeaderValidateLength", v_uint16),
        ("HeaderValidateCopy", v_ptr),
        ("NextAvailableTagIndex", v_uint16),
        ("MaximumTagIndex", v_uint16),
        ("TagEntries", v_ptr),
        ("UCRSegments", v_ptr),
        ("UnusedUnCommittedRanges", v_ptr),
        ("AlignRound", v_uint32),
        ("AlignMask", v_uint32),
        ("VirtualAllocBlocks", ListEntry),
        ("Segments", HeapSegmentArray),
        ("u", HeapUnArray),
        ("u2", HeapUn2Array),
        ("AllocatorBackTraceIndex",v_uint16),
        ("NonDedicatedListLength", v_uint32),
        ("LargeBlocksIndex", v_ptr),
        ("PseudoTagEntries", v_ptr),
        ("FreeLists", HeapFreeListArray),
        ("LockVariable", v_uint32),
        ("CommitRoutine", v_ptr),
        ("FrontEndHeap", v_ptr),
        ("FrontEndHeapLockCount", v_uint16),
        ("FrontEndHeapType", v_uint8),
        ("LastSegmentIndex", v_uint8)
    ]

class EXCEPTION_RECORD(VStruct):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", v_ptr), # Pointer to the next
        ("ExceptionAddress", v_ptr),
        ("NumberParameters", DWORD),
        #("ExceptionInformation", DWORD[NumberParameters])
    ]

class EXCEPTION_REGISTRATION(VStruct):
    _fields_ = [
        ("prev", v_ptr),
        ("handler", v_ptr),
    ]

