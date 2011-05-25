
"""
Some tools that require the envi framework to be installed
"""

import sys
import traceback

import envi
import envi.intel as e_intel # FIXME This should NOT have to be here

class RegisterException(Exception):
    pass

def cmpRegs(emu, trace):
    for idx,name in reg_map:
        er = emu.getRegister(idx)
        tr = trace.getRegisterByName(name)
        if er != tr:
            raise RegisterException("REGISTER MISMATCH: %s 0x%.8x 0x%.8x" % (name, tr, er))
    return True

reg_map = [
    (e_intel.REG_EAX, "eax"),
    (e_intel.REG_ECX, "ecx"),
    (e_intel.REG_EDX, "edx"),
    (e_intel.REG_EBX, "ebx"),
    (e_intel.REG_ESP, "esp"),
    (e_intel.REG_EBP, "ebp"),
    (e_intel.REG_ESI, "esi"),
    (e_intel.REG_EDI, "edi"),
    (e_intel.REG_EIP, "eip"),
    (e_intel.REG_FLAGS, "eflags")
    ]

#FIXME intel specific
def setRegs(emu, trace):
    for idx,name in reg_map:
        tr = trace.getRegisterByName(name)
        emu.setRegister(idx, tr)

def emulatorFromTraceSnapshot(tsnap):
    """
    Produce an envi emulator for this tracer object.  Use the trace's arch
    info to get the emulator so this can be done on the client side of a remote
    vtrace session.
    """
    arch = tsnap.getMeta("Architecture")
    amod = envi.getArchModule(arch)
    emu = amod.getEmulator()

    if tsnap.getMeta("Platform") == "Windows":
        emu.setSegmentInfo(e_intel.SEG_FS, tsnap.getThreads()[tsnap.getMeta("ThreadId")], 0xffffffff)

    emu.setMemoryObject(tsnap)
    setRegs(emu, tsnap)
    return emu

def lockStepEmulator(emu, trace):
    while True:
        print "Lockstep: 0x%.8x" % emu.getProgramCounter()
        try:
            pc = emu.getProgramCounter()
            op = emu.makeOpcode(pc)
            trace.stepi()
            emu.stepi()
            cmpRegs(emu, trace)
        except RegisterException, msg:
            print "Lockstep Error: %s: %s" % (repr(op),msg)
            setRegs(emu, trace)
            sys.stdin.readline()
        except Exception, msg:
            traceback.print_exc()
            print "Lockstep Error: %s" % msg
            return

def main():
    import vtrace
    sym = sys.argv[1]
    pid = int(sys.argv[2])
    t = vtrace.getTrace()
    t.attach(pid)
    symaddr = t.parseExpression(sym)
    t.addBreakpoint(vtrace.Breakpoint(symaddr))
    while t.getProgramCounter() != symaddr:
        t.run()
    snap = t.takeSnapshot()
    #snap.saveToFile("woot.snap") # You may open in vdb to follow along
    emu = emulatorFromTraceSnapshot(snap)
    lockStepEmulator(emu, t)

if __name__ == "__main__":
    # Copy this file out to the vtrace dir for testing and run as main
    main()

