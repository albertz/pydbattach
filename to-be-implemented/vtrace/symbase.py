"""
Symbol resolvers and VSymbol objects.
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import vtrace
import types

class VSymbolResolverException(Exception):
    pass

class VSymbol:
    """
    VSymbol objects contain all the symbol information for
    a particular record.  Use them like a string, and they're
    the symbol name, use them like a number and they're the symbol
    value, call len() on them and you get the length of the symbol
    """
    def __init__(self, name, value, size, stype, fname):
        self.name = name
        self.value = value
        self.size = size
        self.fname = fname
        self.stype = stype

    def __coerce__(self, value):
        # OMG MAGIX
        t = type(value)
        if t == types.NoneType:
            return (True, False)
        return (value, t(self.value))

    def __long__(self):
        return self.value

    def __str__(self):
        return self.name

    def __repr__(self):
        if self.stype == vtrace.SYM_FUNCTION:
            return "%s.%s()" % (self.fname, self.name)
        elif self.stype == vtrace.SYM_SECTION:
            return "%s [%s]" % (self.fname, self.name)
        else:
            return "%s.%s" % (self.fname, self.name)

    def __len__(self):
        return int(self.size)

class VSymbolResolver:
    """
    This class will return symbol values and sizes for
    attribute requests and is mostly for mapping into
    the address space of the expression parser...

    A tracer will instantiate one of these for each file
    loaded, and will be capable of resolving addresses
    """
    def __init__(self, filename, loadbase=0, casesens=True):
        """
        The constructor for SymbolResolver and it's inheritors
        is responsible for either parsing or setting up the
        necessary context to parse when requested.
        """
        self.loaded = False
        self.loadbase = loadbase
        self.filename = filename
        self.casesens = casesens
        self.basename = os.path.basename(filename)
        self.normname = self.basename.split(".")[0].split("-")[0] # FIXME ghettoooooo
        # Make everything lower case if we're not case sensitive
        if not casesens:
            self.normname = self.normname.lower()

        self.symbyname = {}

    def loadUp(self):
        if not self.loaded:
            self.parseBinary()
            self.loaded = True

    def parseBinary(self):
        """
        Over-ride this!  (it wont't get called until a symbol is
        requested, so just load em all up and go.
        """
        self.addSymbol("woot", 0x300, 20, vtrace.SYM_FUNCTION)
        self.addSymbol("foo", 0x400, 20, vtrace.SYM_FUNCTION)

    def addSymbol(self, name, value, size, stype):
        """
        Add a symbol to this resolver.  The "value" field of the symbol
        is expected to be already "fixed up" for the base address in
        the case of relocatable libraries.
        """
        if not self.casesens:
            name = name.lower()
        sym = VSymbol(name, long(value), int(size), stype, self.normname)
        self.symbyname[name] = sym

    def symByName(self, name):
        self.loadUp()
        if not self.casesens:
            name = name.lower()
        x = self.symbyname.get(name, None)
        if x == None:
            raise VSymbolResolverException("ERROR: symbol %s not found in file %s" % (name, self.basename))
        return x

    def symByAddr(self, address):
        self.loadUp()
        #FIXME make this a tree or something
        match = None
        last = 0xffffffff
        for sym in self.symbyname.values():
            saddr = long(sym)
            slen = len(sym)
            # If it's past, skip it...
            if saddr > address:
                continue

            # Are we closer than the last?
            delta = address - saddr

            # Exact match (might be section)
            if address < (saddr + slen): #Exact match
                if sym.stype != vtrace.SYM_SECTION:
                    return sym
                match = sym
                last = delta
                continue

            if delta < last:
                match = sym
                last = delta

        return match

    def symList(self):
        self.loadUp()
        return self.symbyname.values()

    def __nonzero__(self):
        return True

    def __len__(self):
        return len(self.symbyname.keys())

    def __getattr__(self, name):
        """
        Override getattr so things like kernel32.malloc resolve
        """
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError()
        return self.symByName(name)

