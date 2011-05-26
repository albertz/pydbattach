"""
Structures related to PE parsing.
"""

from vstruct.primitives import *
from vstruct import VStruct,VArray

USHORT = v_uint16
ULONG = v_uint32
UCHAR = v_uint8

class dos_reserved(VArray):
    _field_type_ = USHORT
    _field_count_ = 4

class dos_reserved2(VArray):
    _field_type_ = USHORT
    _field_count_ = 10

class IMAGE_DOS_HEADER(VStruct):
    _fields_ = (
        ("e_magic",USHORT),         # Magic number
        ("e_cblp",USHORT),          # Bytes on last page of file
        ("e_cp",USHORT),            # Pages in file
        ("e_crlc",USHORT),          # Relocations
        ("e_cparhdr",USHORT),       # Size of header in paragraphs
        ("e_minalloc",USHORT),      # Minimum extra paragraphs needed
        ("e_maxalloc",USHORT),      # Maximum extra paragraphs needed
        ("e_ss",USHORT),            # Initial (relative) SS value
        ("e_sp",USHORT),            # Initial SP value
        ("e_csum",USHORT),          # Checksum
        ("e_ip",USHORT),            # Initial IP value
        ("e_cs",USHORT),            # Initial (relative) CS value
        ("e_lfarlc",USHORT),        # File address of relocation table
        ("e_ovno",USHORT),          # Overlay number
        ("e_res",dos_reserved),        # Reserved words
        ("e_oemid",USHORT),         # OEM identifier (for e_oeminfo)
        ("e_oeminfo",USHORT),       # OEM information
        ("e_res2", dos_reserved2),  # Reserved words
        ("e_lfanew",ULONG),        # File address of new exe header
    )

class IMAGE_FILE_HEADER(VStruct):
    _fields_ = (
        ("Machine",USHORT),
        ("NumberOfSections", USHORT),
        ("TimeDateStamp", ULONG),
        ("PointerToSymbolTable", ULONG),
        ("NumberOfSymbols", ULONG),
        ("SizeOfOptionalHeader", USHORT),
        ("Ccharacteristics", USHORT),
    )

class IMAGE_DATA_DIRECTORY(VStruct):
    _fields_ = (("VirtualAddress", ULONG),("Size",ULONG))

class data_dir_array(VArray):
    _field_type_ = IMAGE_DATA_DIRECTORY
    _field_count_ = 16

class IMAGE_OPTIONAL_HEADER(VStruct):
    _fields_ = (
        ("Magic",USHORT),
        ("MajorLinkerVersion",UCHAR),
        ("MinorLinkerVersion",UCHAR),
        ("SizeOfCode", ULONG),
        ("SizeOfInitializedData", ULONG),
        ("SizeOfUninitializedData", ULONG),
        ("AddressOfEntryPoint", ULONG),
        ("BaseOfCode", ULONG),
        ("BaseOfData", ULONG),
        #FIXME from here down is the extended NT variant
        ("ImageBase", ULONG),
        ("SectionAlignment", ULONG),
        ("FileAlignment", ULONG),
        ("MajorOperatingSystemVersion", USHORT),
        ("MinorOperatingSystemVersion", USHORT),
        ("MajorImageVersion", USHORT),
        ("MinorImageVersion", USHORT),
        ("MajorSubsystemVersion", USHORT),
        ("MinorSubsystemVersion", USHORT),
        ("Win32VersionValue", ULONG),
        ("SizeOfImage", ULONG),
        ("SizeOfHeaders", ULONG),
        ("CheckSum", ULONG),
        ("Subsystem", USHORT),
        ("DllCharacteristics", USHORT),
        ("SizeOfStackReserve", ULONG),
        ("SizeOfStackCommit", ULONG),
        ("SizeOfHeapReserve", ULONG),
        ("SizeOfHeapCommit", ULONG),
        ("LoaderFlags", ULONG),
        ("NumberOfRvaAndSizes", ULONG),
        ("DataDirectory", data_dir_array),
    )

class IMAGE_NT_HEADERS(VStruct):
    _fields_ = (
        ("Signature", ULONG),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER)
    )

class IMAGE_EXPORT_DIRECTORY(VStruct):
    _fields_ = (
        ("Characteristics", ULONG),
        ("TimeDateStamp", ULONG),
        ("MajorVersion", USHORT),
        ("MinorVersion", USHORT),
        ("Name", ULONG),
        ("Base", ULONG),
        ("NumberOfFunctions", ULONG),
        ("NumberOfNames", ULONG),
        ("AddressOfFunctions", ULONG),
        ("AddressOfNames", ULONG),
        ("AddressOfOrdinals", ULONG),
    )

class ImageName(v_base_t):
    _fmt_ = "8s"

class IMAGE_IMPORT_DIRECTORY(VStruct):
    _fields_ = (
        ("Characteristics", ULONG), # Also PIMAGE_THUNK_DATA union
        ("TimeDateStamp", ULONG),
        ("ForwarderChain", ULONG),
        ("Name", ULONG),
        ("FirstThunk", ULONG), # "pointer" is actually FIXME
    )

class IMAGE_THUNK_DATA(VStruct):
    _fields_ = ()

class IMAGE_SECTION_HEADER(VStruct):
    _fields_ = (
        ("Name", ImageName),
        ("VirtualSize", ULONG),
        ("VirtualAddress", ULONG),
        ("SizeOfRawData", ULONG),       # On disk size
        ("PointerToRawData", ULONG),    # On disk offset
        ("PointerToRelocations", ULONG),
        ("PointerToLineNumbers", ULONG),
        ("NumberOfRelocations", USHORT),
        ("NumberOfLineNumbers", USHORT),
        ("Characteristics", ULONG)
    )

class IMAGE_RESOURCE_DIRECTORY(VStruct):
    _fields_ = (
        ("Characteristics", ULONG),
        ("TimeDateStamp", ULONG),
        ("MajorVersion", USHORT),
        ("MinorVersion", USHORT),
        ("NumberOfNamedEntries", USHORT),
        ("NumberOfIdEntries", USHORT),
    )
