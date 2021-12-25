
"""
A package for parsing structures out into their fields and nest them

These structures are fairly similar to how structures work in ctypes.
I would probably have used ctypes Structure objects except that they
are not pickleable.

"""

import struct
import inspect

from vstruct.primitives import *

class VStructParseException(Exception):
    def __init__(self, structname, wantedsize, gotsize):
        self.sname = structname
        self.wanted = wantedsize
        self.got = gotsize
        Exception.__init__(self, "Struct %s wanted %d bytes but got %d" % (structname, wantedsize, gotsize))

class VStructInvalidField(Exception):
    def __init__(self, sname, fname):
        self.sname = sname
        self.fname = fname
        Exception.__init__(self, "Struct %s has no field %s" % (sname, fname))

def calcformat(vclass):
    """
    Calculate the format for the given vstruct class.  This creates a central
    way for arrays/structs/primatives to be handled for format string creation.
    """
    if vclass._fmt_ == "O": # A VStruct
        base = vclass._endian_
        for name, vtype in vclass._fields_:
            if vtype._fmt_ in ["A","O"]:
                f = calcformat(vtype)
                size = struct.calcsize(f)
                base += "%ds" % size
            else:
                base += vtype._fmt_

    elif vclass._fmt_ == "A": # A VArray

        base = vclass._endian_
        vtype = vclass._field_type_
        if vtype._fmt_ in ["A","O"]:
            f = calcformat(vtype)
            size = struct.calcsize(f)
            base += ("%ds" % size) * vclass._field_count_
        else:
            base += vtype._fmt_ * vclass._field_count_

    else: # A "primative"
        base = vclass._fmt_

    return base

def calcoffset(vclass, fieldname):
    offset = 0
    for name,vsclass in vclass._fields_:
        if name == fieldname:
            return offset
        offset += calcsize(vsclass)
    raise VStructInvalidField(vclass.__name__, fieldname)

def calcsize(vclass):
    return struct.calcsize(calcformat(vclass))

class VArrayIter(object):
    def __init__(self, varray):
        object.__init__(self)
        self.va = varray
        self.max = varray.length
        self.cur = 0

    def next(self):
        if self.cur == self.max:
            raise StopIteration()
        val = self.va[self.cur]
        self.cur += 1
        return val

class VArray(object):
    _fmt_ = "A"
    _field_type_ = None
    _field_count_ = 0
    _endian_ = "<"

    def __init__(self, bytes=None):
        object.__init__(self)
        self.fmt = calcformat(self.__class__)
        self.vtype = self.__class__._field_type_
        self.length = self.__class__._field_count_ # Number of fields
        self.size = struct.calcsize(self.fmt)
        self.values = []
        if bytes == None:
            bytes = "\x00" * self.size

        self.parseBytes(bytes)

    def parseBytes(self, bytes):
        self.values = []
        if len(bytes) != self.size:
            raise VStructParseException(self.__class__.__name__, self.size, len(bytes))
        row = struct.unpack(self.fmt, bytes)
        for val in row:
            self.values.append(self.vtype(val))

    def __repr__(self):
        ret = "\n"
        index = 0
        for x in self:
            ret += "[%d] %s\n" % (index,repr(x))
            index += 1
        return ret

    def __getitem__(self, index):
        return self.values[index]

    def __iter__(self):
        return VArrayIter(self)

    def getPrintInfo(self):
        ret = []
        ret.append((0, "Array: %s" % self.__class__.__name__))
        fsize = calcsize(self.__class__._field_type_)
        for i in range(self.length):
            offset = i * fsize
            e = self[i]
            if isinstance(e, VStruct) or isinstance(e, VArray):
                for soff,stxt in e.getPrintInfo():
                    ret.append((offset+soff,"  %s" % stxt))
            else:
                ret.append((offset, "[%4d] %s" % (i,repr(self[i]))))

        return ret


class VStruct(object):
    """
    The base vstruct object.  This object may be extended *mostly*
    by setting the class-local value _fields_.  Once fields are setup
    you may use a vstruct derived class to parse out byte sequences
    into programatically accessible fields which dereferenceable
    from the instantiated structure object.  Support will probably
    be eventually implemented for writing to those same values
    and zipping it back up into a byte sequence.
    """
    _fields_ = ()
    _fmt_ = 'O'
    _endian_ = "<" # Packed/Little endian by default

    #FIXME eventually support passing in a mem object for write values
    def __init__(self, bytes=None):
        object.__init__(self)
        # Cache our own format
        self.fmt = calcformat(self.__class__)
        self.size = struct.calcsize(self.fmt)

        self.indexes = {} # Index into the list of values keyed by name
        self.offsets = {} # Byte offset into the structure keyed by name
        self.values = []  # Most recently parsed values

        index = 0
        offset = 0
        for name, vtype in self.__class__._fields_:
            self.offsets[name] = offset
            self.indexes[name] = index
            offset += struct.calcsize(calcformat(vtype))
            index += 1

        if bytes == None:
            bytes = "\x00" * self.size

        self.parseBytes(bytes)

    def getPrintInfo(self):
        ret = []
        ret.append((0, "Struct: %s" % self.__class__.__name__))
        for name,ctype in self.__class__._fields_:
            x = getattr(self, name)
            off = self.offsets.get(name)
            if isinstance(x, VStruct) or isinstance(x, VArray):
                for soff,stxt in x.getPrintInfo():
                    ret.append((off+soff, "  %s" % stxt))
            else:
                ret.append((off, "%s: %s" % (name,repr(x))))
        return ret

    def __getstate__(self):
        return (self.fmt, self.size, self.indexes, self.offsets, self.values)

    def __setstate__(self, state):
        (self.fmt,
         self.size,
         self.indexes,
         self.offsets,
         self.values) = state

    def __len__(self):
        return self.size

    def parseBytes(self, bytes):
        self.values = []
        size = len(self)
        if len(bytes) != size:
            raise VStructParseException(self.__class__.__name__, size, len(bytes))

        fields = struct.unpack(self.fmt, bytes)
        for i in range(len(fields)):
            name,vtype = self._fields_[i]
            self.values.append(vtype(fields[i]))

    def getOffset(self, fname):
        """
        Get the offset from this struct to the named field.
        """
        return self.offsets.get(fname)

    def __getattr__(self, name):
        index = self.indexes.get(name, None)
        if index == None:
            raise VStructInvalidField(self.__class__.__name__, name)
        return self.values[index]

    def __repr__(self):
        ret = "Struct %s:\n" % self.__class__.__name__
        for name,ctype in self.__class__._fields_:
            x = getattr(self, name)
            ret += "%s: %s\n" % (name, repr(x))
        return ret


struct_modules = {
}

def registerStructModule(mod):
    name = mod.__name__.split(".")[-1]
    struct_modules[name] = mod

# Our Modules!
import win32
import pe
import elf
registerStructModule(win32)
registerStructModule(pe)
registerStructModule(elf)
# Soon to be python
# Soon to be vista

def getModuleNames():
    """
    Get the list of struct module names which are
    used to access structure classes (namespace).
    """
    return struct_modules.keys()

def getStructNames(modname):
    """
    Get a list of all the known structure names from the
    specified module name
    """
    return getNamesFromModule(struct_modules.get(modname))

def getNamesFromModule(mod):
    ret = []
    for name in dir(mod):
        cls = getattr(mod, name)
        if not inspect.isclass(cls):
            continue
        if issubclass(cls, VStruct):
            ret.append(name)
    ret.sort()
    return ret

def getStructClass(name):
    """
    Get the structure class specified in name.  Name must
    bue a vstruct module.structname combination (ie. win32.PEB).
    """
    if name.find(".") == -1:
        raise Exception("Invalid Structure Name: %s" % name)
    modname,clsname = name.split(".")
    return getattr(struct_modules[modname], clsname)

