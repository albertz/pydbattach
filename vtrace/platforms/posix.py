"""
Posix Signaling Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import sys
import os
import struct
import signal
import platform

import vtrace
import vtrace.symbase as symbase
import vtrace.util as v_util
import Elf
from ctypes import *
import ctypes.util as cutil


libc = None

class PosixMixin:

    """
    A mixin for systems which use POSIX signals and
    things like wait()
    """

    def initMixin(self):
        """
        Setup for the fact that we support signal driven
        debugging on posix platforms
        """
        self.stepping = False # Set this on stepi to diff the TRAP
        self.execing  = False # Set this on exec to diff the TRAP
        self.pthreads = None  # Some platforms make a pthread list

    def platformKill(self):
        self.sendSignal(signal.SIGKILL)

    def sendSignal(self, signo):
        self.requireAttached()
        os.kill(self.pid, signo)

    def platformSendBreak(self):
        self.sendSignal(signal.SIGTRAP) # FIXME maybe change to SIGSTOP

    def posixLibraryLoadHack(self):
        """
        Posix systems don't have library load events, so
        fake it out here... (including pre-populating the
        entire known library bases metadata
        """
        # GHETTO: just look for magic based on binary
        magix = ["\x7fELF",]
        done = []
        for addr,size,perms,fname in self.getMaps():
            if fname in done:
                continue
            done.append(fname)
            if perms & vtrace.MM_READ:
                try:
                    buf = self.readMemory(addr, 20)
                    for m in magix:
                        if buf.find(m) == 0:
                            self.addLibraryBase(fname, addr)
                            break
                except: #FIXME why can't i read all maps?
                    pass

    def platformWait(self):
        pid, status = os.waitpid(self.pid,0)
        return status

    def handleAttach(self):
        self.fireNotifiers(vtrace.NOTIFY_ATTACH)
        self.posixLibraryLoadHack()
        # We'll emulate windows here and send an additional
        # break after our library load events to make things easy
        self.fireNotifiers(vtrace.NOTIFY_BREAK)

    def platformProcessEvent(self, status):

        if os.WIFEXITED(status):
            self.setMeta("ExitCode", os.WEXITSTATUS(status))
            tid = self.getMeta("ThreadId", -1)
            if tid != self.getPid():
                # Set the selected thread ID to the pid cause
                # the old one's invalid
                if self.pthreads != None:
                    self.pthreads.remove(tid)
                self.setMeta("ThreadId", self.getPid())
                self.setMeta("ExitThread", tid)
                self.fireNotifiers(vtrace.NOTIFY_EXIT_THREAD)
            else:
                self.fireNotifiers(vtrace.NOTIFY_EXIT)

        elif os.WIFSIGNALED(status):
            self.setMeta("ExitCode", os.WTERMSIG(status))
            self.fireNotifiers(vtrace.NOTIFY_EXIT)

        elif os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            self.handlePosixSignal(sig)

        else:
            print "OMG WTF JUST HAPPENED??!?11/!?1?>!"

    def handlePosixSignal(self, sig):
        """
        Handle a basic posix signal for this trace.  This was seperated from
        platformProcessEvent so extenders could skim events and still use this logic.
        """
        if sig == signal.SIGTRAP:

            # Traps on posix systems are a little complicated
            if self.stepping:
                self.stepping = False
                self.fireNotifiers(vtrace.NOTIFY_STEP)

            elif self.checkBreakpoints():
                # It was either a known BP or a sendBreak()
                return

            elif self.execing:
                self.execing = False
                self.handleAttach()

            else:
                self.setMeta("PendingSignal", sig)
                self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

        elif sig == signal.SIGSTOP:
            self.handleAttach()

        else:
            self.setMeta("PendingSignal", sig)
            self.fireNotifiers(vtrace.NOTIFY_SIGNAL)

class ElfSymbolResolver(symbase.VSymbolResolver):
    def parseBinary(self):
        typemap = {
            Elf.STT_FUNC:vtrace.SYM_FUNCTION,
            Elf.STT_SECTION:vtrace.SYM_SECTION,
            Elf.STT_OBJECT:vtrace.SYM_GLOBAL
        }

        elf = Elf.Elf(self.filename)
        base = self.loadbase

        # Quick pass to see if we need to assume prelink
        for sec in elf.sections:
            if sec.name != ".text":
                continue
            # Try to detect prelinked
            if sec.sh_addr != sec.sh_offset:
                base = 0
            break

        for sec in elf.sections:
            self.addSymbol(sec.name, sec.sh_addr+base, sec.sh_size, vtrace.SYM_SECTION)

        for sym in elf.symbols:
            self.addSymbol(sym.name, sym.st_value+base, sym.st_size, typemap.get((sym.st_info & 0xf),vtrace.SYM_MISC) )

        for sym in elf.dynamic_symbols:
            self.addSymbol(sym.name, sym.st_value+base, sym.st_size, typemap.get((sym.st_info & 0xf),vtrace.SYM_MISC) )


class ElfMixin:
    """
    A platform mixin to parse Elf binaries
    """
    def platformGetSymbolResolver(self, filename, baseaddr):
        return ElfSymbolResolver(filename, baseaddr)


# As much as I would *love* if all the ptrace defines were the same all the time,
# there seem to be small platform differences...
# These are the ones upon which most agree
PT_TRACE_ME     = 0   # child declares it's being traced */
PT_READ_I       = 1   # read word in child's I space */
PT_READ_D       = 2   # read word in child's D space */
PT_READ_U       = 3   # read word in child's user structure */
PT_WRITE_I      = 4   # write word in child's I space */
PT_WRITE_D      = 5   # write word in child's D space */
PT_WRITE_U      = 6   # write word in child's user structure */
PT_CONTINUE     = 7   # continue the child */
PT_KILL         = 8   # kill the child process */
PT_STEP         = 9   # single step the child */

platform = platform.system()
if platform == "Darwin":
    PT_ATTACH       = 10  # trace some running process */
    PT_DETACH       = 11  # stop tracing a process */
    PT_SIGEXC       = 12  # signals as exceptions for current_proc */
    PT_THUPDATE     = 13  # signal for thread# */
    PT_ATTACHEXC    = 14  # attach to running process with signal exception */
    PT_FORCEQUOTA   = 30  # Enforce quota for root */
    PT_DENY_ATTACH  = 31
    PT_FIRSTMACH    = 32  # for machine-specific requests */

def ptrace(code, pid, addr, data):
    """
    The contents of this call are basically cleanly
    passed to the libc implementation of ptrace.
    """
    global libc
    if not libc:
        cloc = cutil.find_library("c")
        if not cloc:
            raise Exception("ERROR: can't find C library on posix system!")
        libc = CDLL(cloc)
    return libc.ptrace(code, pid, addr, data)

#def waitpid(pid, status, options):
    #global libc
    #if not libc:
        #cloc = cutil.find_library("c")
        #if not cloc:
            #raise Exception("ERROR: can't find C library on posix system!")
        #libc = CDLL(cloc)
    #return libc.waitpid(pid, status, options)

class PtraceMixin:
    """
    A platform mixin for using the ptrace functions
    to attach/detach/continue/stepi etc. Many *nix systems
    will probably use this...

    NOTE: if you get a PT_FOO undefined, it *probably* means that
    the PT_FOO macro isn't defined for that platform (which means
    it need to be done another way like PT_GETREGS on darwin doesn't
    exist... but the darwin mixin over-rides platformGetRegs)
    """

    def initMixin(self):
        """
        Setup supported modes
        """

        self.conthack = 0
        if sys.platform == "darwin":
            self.conthack = 1

        # Make a worker thread do these for us...
        self.threadWrap("platformGetRegs", self.platformGetRegs)
        self.threadWrap("platformSetRegs", self.platformSetRegs)
        self.threadWrap("platformAttach", self.platformAttach)
        self.threadWrap("platformDetach", self.platformDetach)
        self.threadWrap("platformStepi", self.platformStepi)
        self.threadWrap("platformContinue", self.platformContinue)
        self.threadWrap("platformWriteMemory", self.platformWriteMemory)
        self.threadWrap("platformExec", self.platformExec)

    def platformExec(self, cmdline):
        self.execing = True
        cmdlist = v_util.splitargs(cmdline)
        os.stat(cmdlist[0])
        pid = os.fork()
        if pid == 0:
            ptrace(PT_TRACE_ME, 0, 0, 0)
            os.execv(cmdlist[0], cmdlist)
            sys.exit(-1)
        return pid

    def platformWriteMemory(self, address, bytes):
        wordsize = len(struct.pack("P",0))
        remainder = len(bytes) % wordsize

        if remainder:
            pad = self.readMemory(address+(len(bytes)-remainder), wordsize)
            bytes += pad[remainder:]

        for i in range(len(bytes)/wordsize):
            offset = wordsize*i
            dword = struct.unpack("L",bytes[offset:offset+wordsize])[0]
            if ptrace(PT_WRITE_D, self.pid, long(address+offset), long(dword)) != 0:
                raise Exception("ERROR ptrace PT_WRITE_D failed!")


