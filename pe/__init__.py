
#FIXME remember to do dos2unix
import struct
import vstruct
import vstruct.pe as vs_pe

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

class PE(object):
    def __init__(self, fd, inmem=False):
        """
        Construct a PE object.  use inmem=True if you are
        using a MemObjFile or other "memory like" image.
        """
        object.__init__(self)
        self.inmem = inmem
        self.fd = fd
        self.fd.seek(0)

        dosbytes = fd.read(vstruct.calcsize(vs_pe.IMAGE_DOS_HEADER))
        self.IMAGE_DOS_HEADER = vs_pe.IMAGE_DOS_HEADER(dosbytes)

        fd.seek(int(self.IMAGE_DOS_HEADER.e_lfanew))
        ntbytes = fd.read(vstruct.calcsize(vs_pe.IMAGE_NT_HEADERS))
        #FIXME if code offset != sizeof nt headers, maybe old PE... handle them too
        self.IMAGE_NT_HEADERS = vs_pe.IMAGE_NT_HEADERS(ntbytes)

        if int(self.IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader) != 224:
            print "ERROR: SizeOfOptionalHeader != 224"

    def getDllName(self):
        if self.IMAGE_EXPORT_DIRECTORY != None:
            ordoff = self.rvaToOffset(int(self.IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals))
            ordsize = 2 * int(self.IMAGE_EXPORT_DIRECTORY.NumberOfNames)
            return self.readAtOffset(ordoff + ordsize, 32).split("\x00", 1)[0]
        return None

    def getImports(self):
        return self.imports

    def getExports(self):
        return self.exports

    def getForwarders(self):
        return self.forwarders

    def getSections(self):
        return self.sections

    def rvaToOffset(self, rva):
        if self.inmem:
            return rva

        for s in self.sections:
            sbase = int(s.VirtualAddress)
            ssize = int(s.VirtualSize)
            if rva >= sbase and rva < (sbase + ssize):
                return int(s.PointerToRawData) + (rva - sbase)
        return 0

    def getSectionByName(self, name):
        for s in self.getSections():
            if s.Name.value.split("\x00", 1)[0] == name:
                return s
        return None

    def getIdResources(self):
        return self.id_resources

    def getNamedResources(self):
        return self.name_resources

    def parseResources(self):
        self.id_resources = []
        self.name_resources = []
        self.IMAGE_RESOURCE_DIRECTORY = None

        sec = self.getSectionByName(".rsrc")
        if sec == None:
            return 

        irdsize = vstruct.calcsize(vs_pe.IMAGE_RESOURCE_DIRECTORY)
        irdbytes = self.readAtRva(int(sec.VirtualAddress), irdsize)
        self.IMAGE_RESOURCE_DIRECTORY = vs_pe.IMAGE_RESOURCE_DIRECTORY(irdbytes)

        namecount = int(self.IMAGE_RESOURCE_DIRECTORY.NumberOfNamedEntries)
        idcount = int(self.IMAGE_RESOURCE_DIRECTORY.NumberOfIdEntries)
        entsize = 8

        rsrcbase = int(sec.VirtualAddress)

        namebytes = self.readAtRva(rsrcbase + irdsize, namecount * entsize)
        idbytes = self.readAtRva(rsrcbase + irdsize + (namecount*entsize), idcount * entsize)
        while idbytes:
            name,offset = struct.unpack("<LL", idbytes[:entsize])
            offset = offset & 0x7fffffff # HUH?
            if name == 16:
                print self.readAtRva(rsrcbase + offset, 40).encode("hex")
            self.id_resources.append((name,offset))
            idbytes = idbytes[entsize:]

        while namebytes:
            #FIXME parse out the names to be nice.
            name,offset = struct.unpack("<LL", namebytes[:entsize])
            namebytes = namebytes[entsize:]

    def parseSections(self):
        self.sections = []
        off = int(self.IMAGE_DOS_HEADER.e_lfanew) + vstruct.calcsize(vs_pe.IMAGE_NT_HEADERS)
        secsize = vstruct.calcsize(vs_pe.IMAGE_SECTION_HEADER)

        sbytes = self.readAtOffset(off, secsize * int(self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections))
        while sbytes:
            self.sections.append(vs_pe.IMAGE_SECTION_HEADER(sbytes[:secsize]))
            sbytes = sbytes[secsize:]

    def readRvaFormat(self, fmt, rva):
        size = struct.calcsize(fmt)
        bytes = self.readAtRva(rva, size)
        return struct.unpack(fmt, bytes)

    def readAtRva(self, rva, size):
        offset = self.rvaToOffset(rva)
        return self.readAtOffset(offset, size)

    def readAtOffset(self, offset, size):
        #FIXME grab an fd seek lock here?
        ret = ""
        self.fd.seek(offset)
        while len(ret) != size:
            x = self.fd.read(size - len(ret))
            if x == "":
                raise Exception("EOF In readAtOffset()")
            ret += x
        return ret

    def parseImports(self):
        self.imports = []
        self.IMAGE_IMPORT_DIRECTORY = None

        idir = self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        poff = self.rvaToOffset(int(idir.VirtualAddress))

        if poff == 0:
            return

        esize = vstruct.calcsize(vs_pe.IMAGE_IMPORT_DIRECTORY)
        ebytes = self.readAtOffset(poff, esize)
        self.IMAGE_IMPORT_DIRECTORY = vs_pe.IMAGE_IMPORT_DIRECTORY(ebytes)

    def parseExports(self):

        # Initialize our required locals.
        self.exports = []
        self.forwarders = []
        self.IMAGE_EXPORT_DIRECTORY = None

        edir = self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        poff = self.rvaToOffset(int(edir.VirtualAddress))

        if poff == 0: # No exports...
            return

        esize = vstruct.calcsize(vs_pe.IMAGE_EXPORT_DIRECTORY)
        ebytes = self.readAtOffset(poff, esize)
        self.IMAGE_EXPORT_DIRECTORY = vs_pe.IMAGE_EXPORT_DIRECTORY(ebytes)

        funcoff = self.rvaToOffset(int(self.IMAGE_EXPORT_DIRECTORY.AddressOfFunctions))
        funcsize = 4 * int(self.IMAGE_EXPORT_DIRECTORY.NumberOfFunctions)
        funcbytes = self.readAtOffset(funcoff, funcsize)

        nameoff = self.rvaToOffset(int(self.IMAGE_EXPORT_DIRECTORY.AddressOfNames))
        namesize = 4 * int(self.IMAGE_EXPORT_DIRECTORY.NumberOfNames)
        namebytes = self.readAtOffset(nameoff, namesize)

        ordoff = self.rvaToOffset(int(self.IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals))
        ordsize = 2 * int(self.IMAGE_EXPORT_DIRECTORY.NumberOfNames)
        ordbytes = self.readAtOffset(ordoff, ordsize)

        funclist = struct.unpack("%dI" % (len(funcbytes) / 4), funcbytes)
        namelist = struct.unpack("%dI" % (len(namebytes) / 4), namebytes)
        ordlist = struct.unpack("%dH" % (len(ordbytes) / 2), ordbytes)

        base = int(self.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)

        #for i in range(len(funclist)):
        for i in range(len(namelist)):

            ord = ordlist[i]
            nameoff = self.rvaToOffset(namelist[i])
            funcoff = funclist[i]
            ffoff = self.rvaToOffset(funcoff)

            name = None

            if nameoff != 0:
                name = self.readAtOffset(nameoff, 256).split("\x00", 1)[0]
            else:
                name = "ord_%.4x" % ord

            if ffoff >= poff and ffoff < poff + int(edir.Size):
                fwdname = self.readAtOffset(ffoff, 260).split("\x00", 1)[0]
                self.forwarders.append((name,fwdname))
            else:
                self.exports.append((base + funclist[i], ord, name))

    def __getattr__(self, name):
        """
        Use a getattr over-ride to allow "on demand" parsing of particular sections.
        """
        if name == "exports":
            self.parseExports()
            return self.exports

        elif name == "IMAGE_IMPORT_DIRECTORY":
            self.parseImports()
            return self.IMAGE_IMPORT_DIRECTORY

        elif name == "imports":
            self.parseImports()
            return self.imports

        elif name == "IMAGE_EXPORT_DIRECTORY":
            self.parseExports()
            return self.IMAGE_EXPORT_DIRECTORY

        elif name == "forwarders":
            self.parseExports()
            return self.forwarders

        elif name == "sections":
            self.parseSections()
            return self.sections

        elif name == "IMAGE_RESOURCE_DIRECTORY":
            self.parseResources()
            return self.IMAGE_RESOURCE_DIRECTORY

        elif name == "id_resources":
            self.parseResources()
            return self.id_resources

        elif name == "name_resources":
            self.parseResources()
            return self.name_resources

        else:
            raise AttributeError


class MemObjFile:
    """
    A file like object that wraps a MemoryObject (envi) compatable
    object with a file-like object where seek == VA.
    """

    def __init__(self, memobj, baseaddr):
        self.baseaddr = baseaddr
        self.offset = baseaddr
        self.memobj = memobj

    def seek(self, offset):
        self.offset = self.baseaddr + offset

    def read(self, size):
        ret = self.memobj.readMemory(self.offset, size)
        self.offset += size
        return ret
        
    def write(self, bytes):
        self.memobj.writeMemory(self.offset, bytes)
        self.offset += len(bytes)

def peFromMemoryObject(memobj, baseaddr):
    fd = MemObjFile(memobj, baseaddr)
    return PE(fd, inmem=True)

def peFromFileName(fname):
    """
    Utility helper that assures that the file is opened in 
    binary mode which is required for proper functioning.
    """
    f = file(fname, "rb")
    return PE(f)

def peFromBytes(bytes):
    pass
    #make a cStringIO thing

