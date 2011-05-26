"""
Amd64 Support Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import struct

class Amd64Mixin:
    """
    Do what we need to for the lucious amd64
    """
    def getStackTrace(self):
        self.requireAttached()
        current = 0
        sanity = 1000
        frames = []
        rbp = self.getRegisterByName("rbp")
        rip = self.getRegisterByName("rip")
        frames.append((rip,rbp))

        while rbp != 0 and current < sanity:
            try:
                rbp,rip = self.readMemoryFormat(rbp, "=LL")
            except:
                break
            frames.append((rip,rbp))
            current += 1

        return frames

    def getBreakInstruction(self):
        return "\xcc"

    def archGetPcName(self):
        return "rip"

    def archGetSpName(self):
        return "rsp"

