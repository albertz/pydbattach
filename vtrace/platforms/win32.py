"""
Win32 Platform Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import sys
import struct
import traceback
import platform

import PE

import vtrace
import vtrace.symbase as symbase

from ctypes import *
#from ctypes.wintypes import *

platdir = os.path.dirname(__file__)

kernel32 = None
dbghelp = None
psapi = None
ntdll = None
advapi32 = None

# All platforms must be able to import this module (for exceptions etc..)
if sys.platform == "win32":
    kernel32 = windll.kernel32
    ntdll = windll.ntdll
    psapi = windll.psapi
    dbghelp = windll.LoadLibrary(os.path.join(platdir, "dbghelp.dll"))
    advapi32 = windll.advapi32

INFINITE = 0xffffffff
EXCEPTION_MAXIMUM_PARAMETERS = 15

# Debug Event Types
EXCEPTION_DEBUG_EVENT       =1
CREATE_THREAD_DEBUG_EVENT   =2
CREATE_PROCESS_DEBUG_EVENT  =3
EXIT_THREAD_DEBUG_EVENT     =4
EXIT_PROCESS_DEBUG_EVENT    =5
LOAD_DLL_DEBUG_EVENT        =6
UNLOAD_DLL_DEBUG_EVENT      =7
OUTPUT_DEBUG_STRING_EVENT   =8
RIP_EVENT                   =9

# Symbol Flags
SYMFLAG_VALUEPRESENT     = 0x00000001
SYMFLAG_REGISTER         = 0x00000008
SYMFLAG_REGREL           = 0x00000010
SYMFLAG_FRAMEREL         = 0x00000020
SYMFLAG_PARAMETER        = 0x00000040
SYMFLAG_LOCAL            = 0x00000080
SYMFLAG_CONSTANT         = 0x00000100
SYMFLAG_EXPORT           = 0x00000200
SYMFLAG_FORWARDER        = 0x00000400
SYMFLAG_FUNCTION         = 0x00000800
SYMFLAG_VIRTUAL          = 0x00001000
SYMFLAG_THUNK            = 0x00002000
SYMFLAG_TLSREL           = 0x00004000



# Symbol Resolution Options
SYMOPT_CASE_INSENSITIVE         = 0x00000001
SYMOPT_UNDNAME                  = 0x00000002
SYMOPT_DEFERRED_LOADS           = 0x00000004
SYMOPT_NO_CPP                   = 0x00000008
SYMOPT_LOAD_LINES               = 0x00000010
SYMOPT_OMAP_FIND_NEAREST        = 0x00000020
SYMOPT_LOAD_ANYTHING            = 0x00000040
SYMOPT_IGNORE_CVREC             = 0x00000080
SYMOPT_NO_UNQUALIFIED_LOADS     = 0x00000100
SYMOPT_FAIL_CRITICAL_ERRORS     = 0x00000200
SYMOPT_EXACT_SYMBOLS            = 0x00000400
SYMOPT_ALLOW_ABSOLUTE_SYMBOLS   = 0x00000800
SYMOPT_IGNORE_NT_SYMPATH        = 0x00001000
SYMOPT_INCLUDE_32BIT_MODULES    = 0x00002000
SYMOPT_PUBLICS_ONLY             = 0x00004000
SYMOPT_NO_PUBLICS               = 0x00008000
SYMOPT_AUTO_PUBLICS             = 0x00010000
SYMOPT_NO_IMAGE_SEARCH          = 0x00020000
SYMOPT_SECURE                   = 0x00040000
SYMOPT_NO_PROMPTS               = 0x00080000
SYMOPT_DEBUG                    = 0x80000000

# Exception Types
EXCEPTION_WAIT_0                     = 0x00000000L    
EXCEPTION_ABANDONED_WAIT_0           = 0x00000080L    
EXCEPTION_USER_APC                   = 0x000000C0L    
EXCEPTION_TIMEOUT                    = 0x00000102L    
EXCEPTION_PENDING                    = 0x00000103L    
DBG_EXCEPTION_HANDLED             = 0x00010001L    
DBG_CONTINUE                      = 0x00010002L    
EXCEPTION_SEGMENT_NOTIFICATION       = 0x40000005L    
DBG_TERMINATE_THREAD              = 0x40010003L    
DBG_TERMINATE_PROCESS             = 0x40010004L    
DBG_CONTROL_C                     = 0x40010005L    
DBG_CONTROL_BREAK                 = 0x40010008L    
DBG_COMMAND_EXCEPTION             = 0x40010009L    
EXCEPTION_GUARD_PAGE_VIOLATION       = 0x80000001L    
EXCEPTION_DATATYPE_MISALIGNMENT      = 0x80000002L    
EXCEPTION_BREAKPOINT                 = 0x80000003L    
EXCEPTION_SINGLE_STEP                = 0x80000004L    
DBG_EXCEPTION_NOT_HANDLED         = 0x80010001L    
EXCEPTION_ACCESS_VIOLATION           = 0xC0000005L    
EXCEPTION_IN_PAGE_ERROR              = 0xC0000006L    
EXCEPTION_INVALID_HANDLE             = 0xC0000008L    
EXCEPTION_NO_MEMORY                  = 0xC0000017L    
EXCEPTION_ILLEGAL_INSTRUCTION        = 0xC000001DL    
EXCEPTION_NONCONTINUABLE_EXCEPTION   = 0xC0000025L    
EXCEPTION_INVALID_DISPOSITION        = 0xC0000026L    
EXCEPTION_ARRAY_BOUNDS_EXCEEDED      = 0xC000008CL    
EXCEPTION_FLOAT_DENORMAL_OPERAND     = 0xC000008DL    
EXCEPTION_FLOAT_DIVIDE_BY_ZERO       = 0xC000008EL    
EXCEPTION_FLOAT_INEXACT_RESULT       = 0xC000008FL    
EXCEPTION_FLOAT_INVALID_OPERATION    = 0xC0000090L    
EXCEPTION_FLOAT_OVERFLOW             = 0xC0000091L    
EXCEPTION_FLOAT_STACK_CHECK          = 0xC0000092L    
EXCEPTION_FLOAT_UNDERFLOW            = 0xC0000093L    
EXCEPTION_INTEGER_DIVIDE_BY_ZERO     = 0xC0000094L    
EXCEPTION_INTEGER_OVERFLOW           = 0xC0000095L    
EXCEPTION_PRIVILEGED_INSTRUCTION     = 0xC0000096L    
EXCEPTION_STACK_OVERFLOW             = 0xC00000FDL    
EXCEPTION_CONTROL_C_EXIT             = 0xC000013AL    
EXCEPTION_FLOAT_MULTIPLE_FAULTS      = 0xC00002B4L    
EXCEPTION_FLOAT_MULTIPLE_TRAPS       = 0xC00002B5L    
EXCEPTION_REG_NAT_CONSUMPTION        = 0xC00002C9L    

# Context Info
CONTEXT_i386    = 0x00010000    # this assumes that i386 and
CONTEXT_i486    = 0x00010000    # i486 have identical context records
CONTEXT_CONTROL         = (CONTEXT_i386 | 0x00000001L) # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER         = (CONTEXT_i386 | 0x00000002L) # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS        = (CONTEXT_i386 | 0x00000004L) # DS, ES, FS, GS
CONTEXT_FLOATING_POINT  = (CONTEXT_i386 | 0x00000008L) # 387 state
CONTEXT_DEBUG_REGISTERS = (CONTEXT_i386 | 0x00000010L) # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS  = (CONTEXT_i386 | 0x00000020L) # cpu specific extensions
CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)
CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)

# Thread Permissions
THREAD_ALL_ACCESS = 0x001f03ff
PROCESS_ALL_ACCESS = 0x001f0fff

# Memory Permissions
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# Memory States
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000

# Memory Types
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# Process Creation Flags
DEBUG_ONLY_THIS_PROCESS = 0x02

MAX_PATH=260

class EXCEPTION_RECORD(Structure):
    _fields_ = [
            ("ExceptionCode", c_ulong),
            ("ExceptionFlags", c_ulong),
            ("ExceptionRecord", c_ulong),
            ("ExceptionAddress", c_ulong), # Aparently c_void_p can be None
            ("NumberParameters", c_ulong),
            ("ExceptionInformation", c_ulong * EXCEPTION_MAXIMUM_PARAMETERS)
            ]

class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
            ("ExceptionRecord", EXCEPTION_RECORD),
            ("FirstChance", c_ulong)
            ]
class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
            ("Thread", c_ulong),
            ("ThreadLocalBase", c_ulong),
            ("StartAddress", c_ulong)
            ]
class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
            ("File", c_ulong), # HANDLE 
            ("Process", c_ulong), # HANDLE
            ("Thread", c_ulong), # HANDLE
            ("BaseOfImage", c_ulong),
            ("DebugInfoFileOffset", c_ulong),
            ("DebugInfoSize", c_ulong),
            ("ThreadLocalBase", c_ulong),
            ("StartAddress", c_ulong),
            ("ImageName", c_ulong),
            ("Unicode", c_short),
            ]
class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [("ExitCode", c_ulong),]
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("ExitCode", c_ulong),]
class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
            ("File", c_ulong), #HANDLE
            ("BaseOfDll", c_ulong),
            ("DebugInfoFileOffset", c_ulong),
            ("DebugInfoSize", c_ulong),
            ("ImageName", c_ulong),
            ("Unicode", c_ushort),
            ]
class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
            ("BaseOfDll", c_ulong),
            ]
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
            ("DebugStringData", c_ulong), #FIXME 64bit
            ("Unicode", c_ushort),
            ("DebugStringLength", c_ushort),
            ]
class RIP_INFO(Structure):
    _fields_ = [
            ("Error", c_ulong),
            ("Type", c_ulong),
            ]

class DBG_EVENT_UNION(Union):
    _fields_ = [ ("Exception",EXCEPTION_DEBUG_INFO),
                 ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                 ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                 ("ExitThread", EXIT_THREAD_DEBUG_INFO),
                 ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
                 ("LoadDll", LOAD_DLL_DEBUG_INFO),
                 ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
                 ("DebugString", OUTPUT_DEBUG_STRING_INFO),
                 ("RipInfo", RIP_INFO)]

class DEBUG_EVENT(Structure):
    _fields_ = [
            ("DebugEventCode", c_ulong),
            ("ProcessId", c_ulong),
            ("ThreadId", c_ulong),
            ("u", DBG_EVENT_UNION),
            ]

class FloatSavex86(Structure):
    _fields_ = [("ControlWord", c_ulong),
                  ("StatusWord", c_ulong),
                  ("TagWord", c_ulong),
                  ("ErrorOffset", c_ulong),
                  ("ErrorSelector", c_ulong),
                  ("DataOffset", c_ulong),
                  ("DataSelector", c_ulong),
                  ("RegisterSave", c_byte*80),
                  ("Cr0NpxState", c_ulong),
                  ]

class CONTEXTx86(Structure):
    _fields_ = [ ("ContextFlags", c_ulong),
                   ("Dr0", c_ulong),
                   ("Dr1", c_ulong),
                   ("Dr2", c_ulong),
                   ("Dr3", c_ulong),
                   ("Dr4", c_ulong),
                   ("Dr5", c_ulong),
                   ("Dr6", c_ulong),
                   ("Dr7", c_ulong),
                   ("FloatSave", FloatSavex86),
                   ("SegGs", c_ulong),
                   ("SegFs", c_ulong),
                   ("SegEs", c_ulong),
                   ("SegDs", c_ulong),
                   ("edi", c_ulong),
                   ("esi", c_ulong),
                   ("ebx", c_ulong),
                   ("edx", c_ulong),
                   ("ecx", c_ulong),
                   ("eax", c_ulong),
                   ("ebp", c_ulong),
                   ("eip", c_ulong),
                   ("SegCs", c_ulong),
                   ("eflags", c_ulong),
                   ("esp", c_ulong),
                   ("SegSs", c_ulong),
                   ("Extension", c_byte * 512),
                   ]

class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ("BaseAddress", c_ulong),
        ("AllocationBase", c_ulong),
        ("AllocationProtect", c_ulong),
        ("RegionSize", c_ulong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
        ]

class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", c_ulong),
        ("alignment1", c_ulong),
        ("RegionSize", c_ulonglong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
        ("alignment2", c_ulong),
        ]

class STARTUPINFO(Structure):
    """
    Passed into CreateProcess
    """
    _fields_ = [
            ("db", c_ulong),
            ("Reserved", c_char_p),
            ("Desktop", c_char_p),
            ("Title", c_char_p),
            ("X", c_ulong),
            ("Y", c_ulong),
            ("XSize", c_ulong),
            ("YSize", c_ulong),
            ("XCountChars", c_ulong),
            ("YCountChars", c_ulong),
            ("FillAttribute", c_ulong),
            ("Flags", c_ulong),
            ("ShowWindow", c_ushort),
            ("Reserved2", c_ushort),
            ("Reserved3", c_void_p),
            ("StdInput", c_ulong),
            ("StdOutput", c_ulong),
            ("StdError", c_ulong),
            ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
            ("Process", c_ulong),
            ("Thread", c_ulong),
            ("ProcessId", c_ulong),
            ("ThreadId", c_ulong),
            ]

class SYMBOL_INFO(Structure):
    _fields_ = [
                ("SizeOfStruct", c_ulong),
                ("TypeIndex", c_ulong),
                ("Reserved1", c_ulonglong),
                ("Reserved2", c_ulonglong),
                ("Index", c_ulong),
                ("Size", c_ulong),
                ("ModBase", c_ulonglong),
                ("Flags", c_ulong),
                ("Value", c_ulonglong),
                ("Address", c_ulonglong),
                ("Register", c_ulong),
                ("Scope", c_ulong),
                ("Tag", c_ulong),
                ("NameLen", c_ulong),
                ("MaxNameLen", c_ulong),
                ("Name", c_char * 2000), # MAX_SYM_NAME
                ]

class IMAGEHLP_MODULE64(Structure):
    _fields_ = [
            ("SizeOfStruct", c_ulong),
            ("BaseOfImage", c_ulonglong),
            ("ImageSize", c_ulong),
            ("TimeDateStamp", c_ulong),
            ("CheckSum", c_ulong),
            ("NumSyms", c_ulong),
            ("SymType", c_ulong),
            ("ModuleName", c_char*32),
            ("ImageName", c_char*256),
            ("LoadedImageName", c_char*256),
            ("LoadedPdbName", c_char*256),
            ("CvSig", c_ulong),
            ("CvData", c_char*(MAX_PATH*3)),
            ("PdbSig", c_ulong),
            ("PdbSig70", c_char * 16), #GUID
            ("PdbAge", c_ulong),
            ("PdbUnmatched", c_ulong),
            ("DbgUnmatched", c_ulong),
            ("LineNumbers", c_ulong),
            ("GlobalSymbols", c_ulong),
            ("TypeInfo", c_ulong),
            ]


IMAGE_DIRECTORY_ENTRY_EXPORT          =0   # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT          =1   # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE        =2   # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION       =3   # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY        =4   # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC       =5   # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG           =6   # Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT       =7   # (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    =7   # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR       =8   # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS             =9   # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    =10   # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   =11   # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT            =12   # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   =13   # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR =14   # COM Runtime descriptor

IMAGE_DEBUG_TYPE_UNKNOWN          =0
IMAGE_DEBUG_TYPE_COFF             =1
IMAGE_DEBUG_TYPE_CODEVIEW         =2
IMAGE_DEBUG_TYPE_FPO              =3
IMAGE_DEBUG_TYPE_MISC             =4
IMAGE_DEBUG_TYPE_EXCEPTION        =5
IMAGE_DEBUG_TYPE_FIXUP            =6
IMAGE_DEBUG_TYPE_OMAP_TO_SRC      =7
IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    =8
IMAGE_DEBUG_TYPE_BORLAND          =9
IMAGE_DEBUG_TYPE_RESERVED10       =10
IMAGE_DEBUG_TYPE_CLSID            =11

SSRVOPT_CALLBACK            = 0x0001
SSRVOPT_DWORD               = 0x0002
SSRVOPT_DWORDPTR            = 0x0004
SSRVOPT_GUIDPTR             = 0x0008
SSRVOPT_OLDGUIDPTR          = 0x0010
SSRVOPT_UNATTENDED          = 0x0020
SSRVOPT_NOCOPY              = 0x0040
SSRVOPT_PARENTWIN           = 0x0080
SSRVOPT_PARAMTYPE           = 0x0100
SSRVOPT_SECURE              = 0x0200
SSRVOPT_TRACE               = 0x0400
SSRVOPT_SETCONTEXT          = 0x0800
SSRVOPT_PROXY               = 0x1000
SSRVOPT_DOWNSTREAM_STORE    = 0x2000

class IMAGE_DEBUG_DIRECTORY(Structure):
    _fields_ = [
            ("Characteristics", c_ulong),
            ("TimeDateStamp", c_ulong),
            ("MajorVersion", c_ushort),
            ("MinorVersion", c_ushort),
            ("Type", c_ulong),
            ("SizeOfData", c_ulong),
            ("AddressOfRawData", c_ulong),
            ("PointerToRawData", c_ulong),
            ]

NT_LIST_HANDLES = 16

class SYSTEM_HANDLE(Structure):
    _fields_ = [
    ('ProcessID'        , c_ulong),
    ('HandleType'       , c_byte),
    ('Flags'            , c_byte),
    ('HandleNumber' , c_ushort),
    ('KernelAddress'    , c_ulong), #FIXME maybe c_ptr?
    ('GrantedAccess'    , c_ulong),
    ]
PSYSTEM_HANDLE = POINTER(SYSTEM_HANDLE)

# OBJECT_INFORMATION_CLASS
ObjectBasicInformation      = 0
ObjectNameInformation       = 1
ObjectTypeInformation       = 2
ObjectAllTypesInformation   = 3
ObjectHandleInformation     = 4

class UNICODE_STRING(Structure):
    _fields_ = (
        ("Length",c_ushort),
        ("MaximumLength", c_ushort),
        ("Buffer", c_wchar_p)
    )
PUNICODE_STRING = POINTER(UNICODE_STRING)

class OBJECT_TYPE_INFORMATION(Structure):
    _fields_ = (
        ("String",UNICODE_STRING),
        ("reserved", c_uint * 22)
    )

object_type_map = {
    "File":vtrace.FD_FILE,
    "Directory":vtrace.FD_FILE,
    "Event":vtrace.FD_EVENT,
    "KeyedEvent":vtrace.FD_EVENT,
    "Mutant":vtrace.FD_LOCK,
    "Semaphore":vtrace.FD_LOCK,
    "Key":vtrace.FD_REGKEY,
    "Port":vtrace.FD_UNKNOWN,
    "Section":vtrace.FD_UNKNOWN,
    "IoCompletion":vtrace.FD_UNKNOWN,
    "Desktop":vtrace.FD_UNKNOWN,
    "WindowStation":vtrace.FD_UNKNOWN,
}

class LUID(Structure):
    _fields_ = (
        ("LowPart", c_ulong),
        ("HighPart", c_ulong)
    )

class TOKEN_PRIVILEGES(Structure):
    # This isn't really universal, more just for one priv use
    _fields_ = (
        ("PrivilegeCount", c_ulong), # Always one
        ("Privilege", LUID),
        ("PrivilegeAttribute", c_ulong)
    )

SE_PRIVILEGE_ENABLED    = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x00000020
dbgprivdone = False

def getDebugPrivileges():
    tokprivs = TOKEN_PRIVILEGES()
    dbgluid = LUID()
    token = c_uint(0)

    if not advapi32.LookupPrivilegeValueA(0, "seDebugPrivilege", byref(dbgluid)):
        print "LookupPrivilegeValue Failed: %d" % kernel32.GetLastError()
        return False

    if not advapi32.OpenProcessToken(-1, TOKEN_ADJUST_PRIVILEGES, byref(token)):
        print "OpenProcessToken Failed: %d" % kernel32.GetLastError()
        return False

    tokprivs.PrivilegeCount = 1
    tokprivs.Privilege = dbgluid
    tokprivs.PrivilegeAttribute = SE_PRIVILEGE_ENABLED

    if not advapi32.AdjustTokenPrivileges(token, 0, byref(tokprivs), 0, 0, 0):
        kernel32.CloseHandle(token)
        print "OpenProcessToken Failed: %d" % kernel32.GetLastError()
        return False

def buildSystemHandleInformation(count):
    """
    Dynamically build the structure definition for the
    handle info list.
    """
    class SYSTEM_HANDLE_INFORMATION(Structure):
        _fields_ = [ ('Count', c_ulong), ('Handles', SYSTEM_HANDLE * count), ]
    return SYSTEM_HANDLE_INFORMATION()

def raiseWin32Error(name):
    raise vtrace.PlatformException("Win32 Error %s failed: %s" % (name,kernel32.GetLastError()))

def GetModuleFileNameEx(phandle, mhandle):

    buf = create_unicode_buffer(1024)
    psapi.GetModuleFileNameExW(phandle, mhandle, addressof(buf), 1024)
    return buf.value

class Win32Mixin:
    """
    The main mixin for calling the win32 api's via ctypes
    """

    def initMixin(self):
        self.phandle = None
        self.thandles = {}
        self.win32threads = {}
        self.dosdevs = []
        self.flushcache = False
        global dbgprivdone
        if not dbgprivdone:
            dbgprivdone = getDebugPrivileges()

        # Skip the attach event and plow through to the first
        # injected breakpoint (cause libs are loaded by then)
        self.enableAutoContinue(vtrace.NOTIFY_ATTACH)

        # We only set this when we intend to deliver it
        self.setMeta("PendingException", False)

        self.setupDosDeviceMaps()

        # Setup some win32_ver info in metadata
        rel,ver,csd,ptype = platform.win32_ver()
        self.setMeta("WindowsRelease",rel)
        self.setMeta("WindowsVersion", ver)
        self.setMeta("WindowsCsd", csd)
        self.setMeta("WindowsProcessorType", ptype)

        # These activities *must* all be carried out by the same
        # thread on windows.
        self.threadWrap("platformAttach", self.platformAttach)
        self.threadWrap("platformDetach", self.platformDetach)
        self.threadWrap("platformStepi", self.platformStepi)
        self.threadWrap("platformContinue", self.platformContinue)
        self.threadWrap("platformWait", self.platformWait)
        self.threadWrap("platformGetRegs", self.platformGetRegs)
        self.threadWrap("platformSetRegs", self.platformSetRegs)
        self.threadWrap("platformExec", self.platformExec)

    def platformGetFds(self):
        ret = []
        hinfo = self.getHandles()
        for x in range(hinfo.Count):
            if hinfo.Handles[x].ProcessID != self.pid:
                continue
            hand = hinfo.Handles[x].HandleNumber
            myhand = self.dupHandle(hand)
            typestr = self.getHandleInfo(myhand, ObjectTypeInformation)
            namestr = self.getHandleInfo(myhand, ObjectNameInformation)
            kernel32.CloseHandle(myhand)
            htype = object_type_map.get(typestr, vtrace.FD_UNKNOWN)
            ret.append( (hand, htype, "%s: %s" % (typestr,namestr)) )
        return ret

    def dupHandle(self, handle):
        """
        Duplicate the handle (who's id is in the currently attached
        target process) and return our own copy.
        """
        hret = c_uint(0)
        kernel32.DuplicateHandle(self.phandle, handle,
                                 kernel32.GetCurrentProcess(), byref(hret),
                                 0, False, 2) # DUPLICATE_SAME_ACCESS
        return hret.value

    def getHandleInfo(self, handle, itype=ObjectTypeInformation):

        retSiz = c_uint(0)
        buf = create_string_buffer(100)

        ntdll.NtQueryObject(handle, itype,
                buf, sizeof(buf), byref(retSiz))

        realbuf = create_string_buffer(retSiz.value)

        if ntdll.NtQueryObject(handle, itype,
                realbuf, sizeof(realbuf), byref(retSiz)) == 0:

            uString = cast(realbuf, PUNICODE_STRING).contents
            return uString.Buffer
        return "Unknown"

    def getHandles(self):
        hinfo = buildSystemHandleInformation(1)
        hsize = c_ulong(sizeof(hinfo))

        ntdll.NtQuerySystemInformation(NT_LIST_HANDLES, addressof(hinfo), hsize, addressof(hsize))

        count = (hsize.value-4) / sizeof(SYSTEM_HANDLE)
        hinfo = buildSystemHandleInformation(count)
        hsize = c_ulong(sizeof(hinfo))

        ntdll.NtQuerySystemInformation(NT_LIST_HANDLES, addressof(hinfo), hsize, None)

        return hinfo


    def setupDosDeviceMaps(self):
        self.dosdevs = []
        dname = (c_char * 512)()
        size = kernel32.GetLogicalDriveStringsA(512, addressof(dname))
        devs = dname.raw[:size-1].split("\x00")
        for dev in devs:
            dosname = "%s:" % dev[0]
            kernel32.QueryDosDeviceA("%s:" % dev[0], addressof(dname), 512)
            self.dosdevs.append( (dosname, dname.value) )

    def platformKill(self):
        kernel32.TerminateProcess(self.phandle, 0)

    def getRegisterFormat(self):
        return "51L"

    def getRegisterNames(self):
        return ("ContextFlags","debug0","debug1","debug2","debug3",
                "debug6","debug7","ControlWord","StatusWord","TagWord",
                "ErrorOffset","ErrorSelector","DataOffset","DataSelector",
                # A bunch of float stuff that I'm not parsing just yet..
                "fa0","fa1","fa2","fa3","fa4","fa5","fa6","fa7","fa8","fa9",
                "fa10","fa11","fa12","fa13","fa14","fa15","fa16","fa17","fa18","fa19",
                "Cr0NpxState","gs","fs","es","ds",
                "edi","esi","ebx","edx","ecx","eax","ebp","eip","cs","eflags",
                "esp","ss")

    def platformExec(self, cmdline):
        sinfo = STARTUPINFO()
        pinfo = PROCESS_INFORMATION()
        if not kernel32.CreateProcessA(0, cmdline, 0, 0, 0,
                DEBUG_ONLY_THIS_PROCESS, 0, 0, addressof(sinfo), addressof(pinfo)):
            raise Exception("CreateProcess failed!")

        # When launching an app, we're guaranteed to get a breakpoint
        # Unless we want to fail checkBreakpoints, we'll need to set ShouldBreak
        self.setMeta('ShouldBreak', True)

        return pinfo.ProcessId

    def platformInjectSo(self, filename):
        try:
            lla = self.parseExpression("kernel32.LoadLibraryA")
        except:
            raise Exception("ERROR: symbol kernel32.LoadLibraryA not found!")
        regs = self.platformCall(lla, [filename,])
        if regs == None:
            raise Exception("ERROR: platformCall for LoadLibraryA Failed!")
        return regs.get("eax", 0)
        
    def platformAttach(self, pid):
        if not kernel32.DebugActiveProcess(pid):
            raiseWin32Error("DebugActiveProcess")

    def platformDetach(self):
        # Do the crazy "can't supress exceptions from detach" dance.
        if ((not self.exited) and
            self.getCurrentBreakpoint() != None):
            self.cleanupBreakpoints()
            self.platformContinue()
            self.platformSendBreak()
            self.platformWait()
        if not kernel32.DebugActiveProcessStop(self.pid):
            raiseWin32Error("DebugActiveProcessStop")
        kernel32.CloseHandle(self.phandle)
        self.phandle = None

    def platformAllocateMemory(self, size, perms=vtrace.MM_RWX, suggestaddr=0):
        #FIXME handle permissions
        ret = kernel32.VirtualAllocEx(self.phandle,
                suggestaddr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if ret == 0:
            raiseWin32Error("VirtualAllocEx")
        return ret

    def platformReadMemory(self, address, size):
        btype = c_char * size
        buf = btype()
        ret = c_ulong(0)
        if not kernel32.ReadProcessMemory(self.phandle, address, addressof(buf), size, addressof(ret)):
            raiseWin32Error("ReadProcessMemory")
        return buf.raw

    def platformContinue(self):

        magic = DBG_CONTINUE

        if self.getMeta("PendingException"):
            magic = DBG_EXCEPTION_NOT_HANDLED

        self.setMeta("PendingException", False)
        if self.flushcache:
            self.flushcache = False
            kernel32.FlushInstructionCache(self.phandle, 0, 0)
        if not kernel32.ContinueDebugEvent(self.pid, self.getMeta("StoppedThreadId"), magic):
            raiseWin32Error("ContinueDebugEvent")

    def platformStepi(self):
        self.setEflagsTf()
        self.syncRegs()
        self.platformContinue()

    def platformWriteMemory(self, address, buf):
        ret = c_ulong(0)
        if not kernel32.WriteProcessMemory(self.phandle, address, buf, len(buf), addressof(ret)):
            raiseWin32Error("WriteProcessMemory")
        # If we wrote memory, flush the instruction cache...
        self.flushcache = True
        return ret.value

    def platformGetRegs(self):
        ctx = CONTEXTx86()
        ctx.ContextFlags = (CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS)
        thandle = self.thandles.get(self.getMeta("ThreadId", 0), None)
        if not thandle:
            raise Exception("Getting registers for unknown thread")
        if not kernel32.GetThreadContext(thandle, addressof(ctx)):
            raiseWin32Error("GetThreadContext")
        return string_at(addressof(ctx), sizeof(ctx))

    def platformSetRegs(self, bytes):
        buf = c_buffer(bytes)
        ctx = CONTEXTx86()
        thandle = self.thandles.get(self.getMeta("ThreadId", 0), None)
        if not thandle:
            raise Exception("Getting registers for unknown thread")
        if not kernel32.GetThreadContext(thandle, addressof(ctx)):
            raiseWin32Error("GetThreadContext")

        memmove(addressof(ctx), addressof(buf), len(bytes))
        ctx.ContextFlags = (CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS)

        if not kernel32.SetThreadContext(thandle, addressof(ctx)):
            raiseWin32Error("SetThreadContext")

    def platformSendBreak(self):
        #FIXME make this support windows 2000
        if not kernel32.DebugBreakProcess(self.phandle):
            raiseWin32Error("DebugBreakProcess")

    def platformPs(self):
        ret = []
        pcount = 128 # Hardcoded limit of 128 processes... oh well..
        pids = (c_int * pcount)()
        needed = c_int(0)
        hmodule = c_int(0)

        psapi.EnumProcesses(addressof(pids), 4*pcount, addressof(needed))
        for i in range(needed.value/4):
            fname = (c_wchar * 512)()
            phandle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, 0, pids[i])
            if not phandle: # If we get 0, we failed to open it (perms)
                continue
            psapi.EnumProcessModules(phandle, addressof(hmodule), 4, addressof(needed))
            psapi.GetModuleBaseNameW(phandle, hmodule, fname, 512)
            ret.append( (pids[i], fname.value))
            kernel32.CloseHandle(phandle)
            kernel32.CloseHandle(hmodule)
        return ret

    def platformWait(self):
        event = DEBUG_EVENT()
        if not kernel32.WaitForDebugEvent(addressof(event), INFINITE):
            raiseWin32Error("WaitForDebugEvent")
        return event

    def platformProcessEvent(self, event):

        if event.ProcessId != self.pid:
            raise Exception("ERROR - Win32 Edge Condition One")

        ThreadId = event.ThreadId
        eventdict = {} # Each handler fills this in
        self.setMeta("Win32Event", eventdict)
        self.setMeta("StoppedThreadId", ThreadId)
        self.setMeta("ThreadId", ThreadId)

        if event.DebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
           self.phandle = event.u.CreateProcessInfo.Process
           baseaddr = event.u.CreateProcessInfo.BaseOfImage
           ImageName = GetModuleFileNameEx(self.phandle, 0)
           self.setMeta("ExeName", ImageName)

           teb = event.u.CreateProcessInfo.ThreadLocalBase
           self.win32threads[ThreadId] = teb
           self.thandles[ThreadId] = event.u.CreateProcessInfo.Thread

           peb, = self.readMemoryFormat(teb + 0x30, "L")
           self.setMeta("PEB", peb)

           eventdict["ImageName"] = ImageName
           eventdict["StartAddress"] = event.u.CreateProcessInfo.StartAddress
           eventdict["ThreadLocalBase"] = teb

           self.fireNotifiers(vtrace.NOTIFY_ATTACH)
           self.addLibraryBase(ImageName, baseaddr)

        elif event.DebugEventCode == CREATE_THREAD_DEBUG_EVENT:
            self.thandles[ThreadId] = event.u.CreateThread.Thread
            teb = event.u.CreateThread.ThreadLocalBase
            startaddr = event.u.CreateThread.StartAddress
            # Setup the event dictionary for notifiers
            eventdict["ThreadLocalBase"] = teb
            eventdict["StartAddress"] = startaddr
            self.win32threads[ThreadId] = teb
            self.fireNotifiers(vtrace.NOTIFY_CREATE_THREAD)

        elif event.DebugEventCode == EXCEPTION_DEBUG_EVENT:
            excode = event.u.Exception.ExceptionRecord.ExceptionCode
            exflags = event.u.Exception.ExceptionRecord.ExceptionFlags
            exaddr = event.u.Exception.ExceptionRecord.ExceptionAddress
            exparam = event.u.Exception.ExceptionRecord.NumberParameters
            firstChance = event.u.Exception.FirstChance

            plist = []
            for i in range(exparam):
                plist.append(event.u.Exception.ExceptionRecord.ExceptionInformation[i])

            eventdict["ExceptionCode"] = excode
            eventdict["ExceptionFlags"] = exflags
            eventdict["ExceptionAddress"] = exaddr
            eventdict["NumberParameters"] = exparam
            eventdict["FirstChance"] = bool(firstChance)
            eventdict["ExceptionInformation"] = plist

            if firstChance:

                if excode == EXCEPTION_BREAKPOINT:
                    self.setMeta("PendingException", False)
                    if not self.checkBreakpoints():
                        # On first attach, all the library load
                        # events occur, then we hit a CC.  So,
                        # if we don't find a breakpoint, notify
                        # break anyay....
                        self.fireNotifiers(vtrace.NOTIFY_BREAK)
                        # Don't eat the BP exception if we didn't make it...
                        # Actually, for win2k's sake, let's do eat the breaks
                        #self.setMeta("PendingException", True)

                elif excode == EXCEPTION_SINGLE_STEP:
                    self.setMeta("PendingException", False)
                    self.fireNotifiers(vtrace.NOTIFY_STEP)

                else:
                    self.setMeta("PendingException", True)
                    self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

            else:
                self.setMeta("PendingException", True)
                self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

        elif event.DebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
            ecode = event.u.ExitProcess.ExitCode
            eventdict["ExitCode"] = ecode
            self.setMeta("ExitCode", ecode)
            self.fireNotifiers(vtrace.NOTIFY_EXIT)
            self.platformDetach()

        elif event.DebugEventCode == EXIT_THREAD_DEBUG_EVENT:
            self.win32threads.pop(ThreadId, None)
            ecode = event.u.ExitThread.ExitCode
            eventdict["ExitCode"] = ecode
            self.setMeta("ExitCode", ecode)
            self.setMeta("ExitThread", ThreadId)
            self.fireNotifiers(vtrace.NOTIFY_EXIT_THREAD)

        elif event.DebugEventCode == LOAD_DLL_DEBUG_EVENT:
            baseaddr = event.u.LoadDll.BaseOfDll
            ImageName = GetModuleFileNameEx(self.phandle, baseaddr)
            if not ImageName:
                # If it fails, fall back on getMappedFileName
                ImageName = self.getMappedFileName(baseaddr)
            self.addLibraryBase(ImageName, baseaddr)
            kernel32.CloseHandle(event.u.LoadDll.File)

        elif event.DebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
            eventdict["BaseOfDll"] = event.u.UnloadDll.BaseOfDll
            self.fireNotifiers(vtrace.NOTIFY_UNLOAD_LIBRARY)

        elif event.DebugEventCode == OUTPUT_DEBUG_STRING_EVENT:
            # Gotta have a way to continue these...
            d = event.u.DebugString
            sdata = d.DebugStringData
            ssize = d.DebugStringLength

            # FIXME possibly make a gofast option that
            # doesn't get the string
            mem = self.readMemory(sdata, ssize)
            if d.Unicode:
                mem = mem.decode("utf-16-le")
            eventdict["DebugString"] = mem
            self.fireNotifiers(vtrace.NOTIFY_DEBUG_PRINT)

        else:
            print "Currently unhandled event",code


    def getMappedFileName(self, address):
        self.requireAttached()
        fname = (c_wchar * 512)()
        x = psapi.GetMappedFileNameW(self.phandle, address, addressof(fname), 512)
        if not x:
            return ""
        name = fname.value
        for dosname, devname in self.dosdevs:
            if name.startswith(devname):
                return name.replace(devname, dosname)
        return name

    def platformGetMaps(self):
        ret = []
        base = 0
        mbi = MEMORY_BASIC_INFORMATION32()
        while kernel32.VirtualQueryEx(self.phandle, base, addressof(mbi), sizeof(mbi)) > 0:
            if mbi.State == MEM_COMMIT:
                prot = mbi.Protect & 0xff
                if prot == PAGE_READONLY:
                    perm = vtrace.MM_READ
                elif prot == PAGE_READWRITE:
                    perm = vtrace.MM_READ | vtrace.MM_WRITE
                elif prot == PAGE_WRITECOPY:
                    perm = vtrace.MM_READ | vtrace.MM_WRITE
                elif prot == PAGE_EXECUTE:
                    perm = vtrace.MM_EXEC
                elif prot == PAGE_EXECUTE_READ:
                    perm = vtrace.MM_EXEC | vtrace.MM_READ
                elif prot == PAGE_EXECUTE_READWRITE:
                    perm = vtrace.MM_EXEC | vtrace.MM_READ | vtrace.MM_WRITE
                elif prot == PAGE_EXECUTE_WRITECOPY:
                    perm = vtrace.MM_EXEC | vtrace.MM_READ | vtrace.MM_WRITE
                else:
                    perm = 0

                base = mbi.BaseAddress
                mname = self.getMappedFileName(base)
                # If it fails, fall back on getmodulefilename
                if mname == "":
                    mname = GetModuleFileNameEx(self.phandle, base)
                ret.append( (base, mbi.RegionSize, perm, mname) )

            base += mbi.RegionSize
        return ret

    def platformGetThreads(self):
        return self.win32threads

if sys.platform == "win32":
    SYMCALLBACK = WINFUNCTYPE(c_int, POINTER(SYMBOL_INFO), c_ulong, c_ulong)
    PDBCALLBACK = WINFUNCTYPE(c_int, c_char_p, c_void_p)

class Win32SymbolResolver(symbase.VSymbolResolver):
    def __init__(self, filename, baseaddr, handle):
        # All locals must be in constructor because of the
        # getattr over-ride..
        self.phandle = handle
        self.doff = 0
        self.file = None
        self.doshdr = None
        self.pehdr = None
        self.sections = []
        self.funcflags = (SYMFLAG_FUNCTION | SYMFLAG_EXPORT)
        self.dbghelp_symopts = (SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS | SYMOPT_NO_CPP)
        symbase.VSymbolResolver.__init__(self, filename, baseaddr, casesens=False)

    def rvaToFileOffset(self, rva):
        ret = 0
        for sname,srva,svsiz,sroff,srsiz in self.sections:
            if (srva <= rva) and (srva+svsiz >= rva):
                ret = (sroff + (rva-srva))
                break
        return ret

    def printSymbolInfo(self, info):
        # Just a helper function for "reversing" how dbghelp works
        for n,t in info.__class__._fields_:
            print n,repr(getattr(info, n))

    def typeEnumCallback(self, psym, size, ctx):
        sym = psym.contents
        #self.printSymbolInfo(sym)
        #print "TYPE",sym.Name,hex(sym.Flags)
        return True

    def symEnumCallback(self, psym, size, ctx):
        sym = psym.contents
        #self.printSymbolInfo(sym)
        #FIXME ms doesn't mostly include flags, they are really all misc...
        if sym.Flags & self.funcflags:
            self.addSymbol(sym.Name, sym.Address, size, vtrace.SYM_FUNCTION)
        else:
            self.addSymbol(sym.Name, sym.Address, size, vtrace.SYM_MISC)
        return True

    def symFileCallback(self, filename, nothing):
        return 0

    def parseWithDbgHelp(self):
        try:

            dbghelp.SymInitialize(self.phandle, None, False)
            dbghelp.SymSetOptions(self.dbghelp_symopts)

            x = dbghelp.SymLoadModule64(self.phandle,
                        0, 
                        c_char_p(self.filename),
                        None,
                        c_ulonglong(self.loadbase),
                        None)

            # This is for debugging which pdb got loaded
            #imghlp = IMAGEHLP_MODULE64()
            #dbghelp.SymGetModuleInfo64(None, c_ulonglong(x), addressof(imghlp))
            #print "PDB",imghlp.LoadedPdbName

            dbghelp.SymEnumSymbols(self.phandle,
                        c_ulonglong(self.loadbase),
                        None,
                        SYMCALLBACK(self.symEnumCallback),
                        0)

            # This is how you enumerate type information
            #dbghelp.SymEnumTypes(self.phandle,
                        #c_ulonglong(self.loadbase),
                        #SYMCALLBACK(self.typeEnumCallback),
                        #0)

            dbghelp.SymCleanup(self.phandle)

        except Exception, e:
            traceback.print_exc()
            raise

    def readPeHeader(self):
        self.doff = 0
        dosfmt = "<30HI"
        pefmt = "<I2H3I2H"

        self.doshdr = self.readPeFmt(dosfmt, 0)
        #FIXME check mz

        # Last element in the dos header is the address
        # of the pe header...
        self.file.seek(self.doshdr[-1])
        self.pehdr = self.readPeFmt(pefmt, self.doshdr[-1])

        if self.pehdr[6] == 224: # optional header length
            #peheader + sizeof(pehdr) + offset to data dictionary
            self.doff = self.doshdr[-1] + 24 + 96

    def readPeFmt(self, fmt, offset=None):
        size = struct.calcsize(fmt)
        if offset != None:
            self.file.seek(offset)
        return struct.unpack(fmt, self.file.read(size))

    def readPeSections(self):
        """
        This assumes that readPeHeader has been called
        but doesn't assume any particular file offset
        """
        self.sections = []
        self.file.seek(self.doshdr[-1] + self.pehdr[6] + 24)  # Seek to pehdr + aoutsize
        for i in range(self.pehdr[2]): # seccnt
            (name, vsize, rva,
             rsize, roffset, RelOff,
             LineOff, RelSize, LineSize,
             Chars) = self.readPeFmt("<8s6I2HI")
            sname = name.strip("\x00")
            soff = self.loadbase + rva
            self.sections.append((sname, rva, vsize, roffset, rsize))
            self.addSymbol(sname, soff, vsize, vtrace.SYM_SECTION)

    def initialParse(self):
        self.file = file(self.filename, "rb")
        self.readPeHeader()
        self.readPeSections()

    def parseBinary(self):
        self.initialParse()
        self.parseWithDbgHelp()

class PEMixin:
    """
    A platform mixin to parse PE binaries
    """
    def platformGetSymbolResolver(self, filename, baseaddr):
        return Win32SymbolResolver(filename, baseaddr, self.phandle)

