"""
Elf structure definitions
"""

from vstruct import VStruct,VArray
from vstruct.primitives import *

class Elf32Symbol(VStruct):
    _fields_ =  [
        ("st_name", v_uint32),
        ("st_value", v_uint32),
        ("st_size", v_uint32),
        ("st_info", v_uint8),
        ("st_other", v_uint8),
        ("st_shndx", v_uint16)
    ]

class Elf32Reloc(VStruct):
    _fields_ = [
        ("r_offset", v_ptr),
        ("r_info", v_uint32),
    ]

    def getType(self):
        return int(self.r_info) & 0xff

    def getSymTabIndex(self):
        return int(self.r_info) >> 8

class Elf32Dynamic(VStruct):
    _fields_ = [
        ("d_tag", v_uint32),
        ("d_value", v_uint32),
    ]

class Elf64Symbol(VStruct):
    pass

