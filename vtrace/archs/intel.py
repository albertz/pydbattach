"""
x86 Support Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import vtrace
import struct
import traceback
import types
import vtrace.breakpoints as breakpoints

class IntelMixin:
    def archAddWatchpoint(self, address):
        regs = self.getRegisters()
        if not regs.has_key("debug7"):
            raise Exception("ERROR: Intel debug status register not found!")
        status = regs["debug7"]
        for i in range(4):
            if regs["debug%d" % i] != 0:
                continue

            regs["debug%d" % i] = address

            status |= 1 << (2*i)
            mask = 3 # FIXME 3 for read/write
            status |= (mask << (16+(4*i)))

            print "ADDING 0x%.8x at index %d status 0x%.8x" % (address,i,status)

            regs["debug7"] = status
            self.setRegisters(regs)
            return
            
        raise Exception("ERROR: there...  are... 4... debug registers!")

    def archRemWatchpoint(self, address):
        regs = self.getRegisters()
        if not regs.has_key("debug7"):
            raise Exception("ERROR: Intel debug status register not found!")
        status = regs["debug7"]
        for i in range(4):
            if regs["debug%d"] == address:
                status &= ~(1 << 2*i)
                # Always use 3 to mask off both bits...
                status &= ~(3 << 16+(4*i))

                regs["debug%d" % i] = 0
                regs["debug7"] = status

                self.setRegisters(regs)
                return

    def archCheckWatchpoints(self):
        regs = self.getRegisters()
        if not regs.has_key("debug7"):
            return False
        debug6 = regs["debug6"]
        x = debug6 & 0x0f
        if not x:
            return False
        regs["debug6"] = debug6 & ~(0x0f)
        self.setRegisters(regs)
        for i in range(4):
            if x >> i == 1:
                return regs["debug%d" % i]

    def setEflagsTf(self, enabled=True):
        """
        A convenience function to flip the TF flag in the eflags
        register
        """
        eflags = self.getRegisterByName("eflags")
        if enabled:
            eflags |= 0x100 # TF flag
        else:
            eflags &= ~0x100 # TF flag
        self.setRegisterByName("eflags",eflags)

    def getStackTrace(self):
        self.requireAttached()
        current = 0
        sanity = 1000
        frames = []
        ebp = self.getRegisterByName("ebp")
        eip = self.getRegisterByName("eip")
        frames.append((eip,ebp))

        while ebp != 0 and current < sanity:
            try:
                buf = self.readMemory(ebp, 8)
                ebp,eip = struct.unpack("<LL",buf)
                frames.append((eip,ebp))
                current += 1
            except:
                break

        return frames

    def getBreakInstruction(self):
        return "\xcc"

    def archGetPcName(self):
        return "eip"

    def archGetSpName(self):
        return "esp"

    def platformCall(self, address, args, convention=None):
        buf = ""
        finalargs = []
        saved_regs = self.getRegisters()
        sp = self.getStackCounter()
        pc = self.getProgramCounter()

        for arg in args:
            if type(arg) == types.StringType: # Nicly map strings into mem
                buf = arg+"\x00\x00"+buf    # Pad with a null for convenience
                finalargs.append(sp - len(buf))
            else:
                finalargs.append(arg)

        m = len(buf) % 4
        if m:
            buf = ("\x00" * (4-m)) + buf

        # Args are 
        #finalargs.reverse()
        buf = struct.pack("<%dL" % len(finalargs), *finalargs) + buf

        # Saved EIP is target addr so when we hit the break...
        buf = struct.pack("<L", address) + buf
        # Calc the new stack pointer
        newsp = sp-len(buf)
        # Write the stack buffer in
        self.writeMemory(newsp, buf)
        # Setup the stack pointer
        self.setStackCounter(newsp)
        # Setup the instruction pointer
        self.setProgramCounter(address)
        # Add the magical call-break
        callbreak = breakpoints.CallBreak(address, saved_regs)
        self.addBreakpoint(callbreak)
        # Continue until the CallBreak has been hit
        while not callbreak.endregs:
            self.run()
        return callbreak.endregs

