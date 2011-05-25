
import vstruct

HEAP_ENTRY_BUSY             = 0x01
HEAP_ENTRY_EXTRA_PRESENT    = 0x02
HEAP_ENTRY_FILL_PATTERN     = 0x04
HEAP_ENTRY_VIRTUAL_ALLOC    = 0x08
HEAP_ENTRY_LAST_ENTRY       = 0x10
HEAP_ENTRY_SETTABLE_FLAG1   = 0x20
HEAP_ENTRY_SETTABLE_FLAG2   = 0x40
HEAP_ENTRY_SETTABLE_FLAG3   = 0x80

def reprHeapFlags(flags):
    ret = []
    if flags & HEAP_ENTRY_BUSY:
        ret.append("BUSY")
    if flags & HEAP_ENTRY_FILL_PATTERN:
        ret.append("FILL")
    if flags & HEAP_ENTRY_LAST_ENTRY:
        ret.append("LAST")
    if len(ret):
        return "|".join(ret)
    return "NONE"

class HeapCorruptionException(Exception):
    def __init__(self, heap, segment, chunkaddr):
        Exception.__init__(self, "Heap: 0x%.8x Segment: 0x%.8x Chunk Address: 0x%.8x" % (
                                 heap.address, segment.address, chunkaddr))
        self.heap = heap
        self.segment = segment
        self.chunkaddr = chunkaddr

class FreeListCorruption(Exception):
    def __init__(self, heap, index):
        Exception.__init__(self, "Heap: 0x%.8x FreeList Index: %d" % (heap.address, index))
        self.heap = heap
        self.index = index

class ChunkNotFound(Exception):
    pass

def getHeapSegChunk(trace, address):
    """
    Find and return the heap, segment, and chunk for the given addres
    (or exception).
    """
    for heap in getHeaps(trace):
        for seg in heap.getSegments():
            base,size,perms,fname = trace.getMap(seg.address)
            if address < base or address > base+size:
                continue
            for chunk in seg.getChunks():
                a = chunk.address
                b = chunk.address + len(chunk)
                if (address >= a and address < b):
                    return heap,seg,chunk

    raise ChunkNotFound("No Chunk Found for 0x%.8x" % address)

def getHeaps(trace):
    """
    Get the win32 heaps (returns a list of Win32Heap objects)
    """
    ret = []
    pebaddr = trace.getMeta("PEB")
    peb = trace.getStruct("win32.PEB", pebaddr)
    heapcount = int(peb.NumberOfHeaps)
    # FIXME not 64bit ok
    hlist = trace.readMemoryFormat(long(peb.ProcessHeaps), "<"+("L"*heapcount))
    for haddr in hlist:
        ret.append(Win32Heap(trace, haddr))
    return ret

class Win32Heap:

    def __init__(self, trace, address):
        self.address = address
        self.trace = trace
        self.heap = trace.getStruct("win32.HEAP", address)
        self.seglist = None

    def getSegments(self):
        """
        Return a list of Win32Segment objects.
        """
        if self.seglist == None:
            self.seglist = []
            for i in range(long(self.heap.LastSegmentIndex)+1):
                sa = self.heap.Segments[i]
                self.seglist.append(Win32Segment(self.trace, self, long(sa)))
        return self.seglist

class Win32Segment:
    def __init__(self, trace, heap, address):
        self.trace = trace
        self.heap = heap
        self.address = address
        self.seg = trace.getStruct("win32.HEAP_ENTRY", address)
        #FIXME segments can specify chunk Size granularity
        self.chunks = None

    def getChunks(self):
        if self.chunks == None:
            self.chunks = []
            addr = self.address
            lastsize = None
            while True:
                chunk = Win32Chunk(self.trace, addr)
                addr += len(chunk)
                self.chunks.append(chunk)
                if lastsize != None:
                    if int(chunk.chunk.PrevSize) * 8 != lastsize:
                        raise HeapCorruptionException(self.heap, self, addr)
                if chunk.isLast():
                    break
                lastsize = len(chunk)
        return self.chunks

class Win32Chunk:
    def __init__(self, trace, address):
        self.trace = trace
        self.address = address
        self.chunk = trace.getStruct("win32.HEAP_ENTRY", address)

    def __len__(self):
        return int(self.chunk.Size) * 8

    def isLast(self):
        return bool(int(self.chunk.Flags) & HEAP_ENTRY_LAST_ENTRY)

    def isBusy(self):
        return bool(int(self.chunk.Flags) & HEAP_ENTRY_BUSY)

    def getDataAddress(self):
        return self.address + len(self.chunk)

    def getDataSize(self):
        return len(self) - len(self.chunk)

    def getDataBytes(self, maxsize=None):
        size = self.getDataSize()
        if maxsize != None:
            size = min(size, maxsize)
        return self.trace.readMemory(self.getDataAddress(), size)

    def reprFlags(self):
        return reprHeapFlags(int(self.chunk.Flags))

