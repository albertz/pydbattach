"""
Darwin Platform Module
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import struct
import signal
import vtrace
import vtrace.platforms.posix as v_posix
import vtrace.symbase as symbase

class MachoSymbolResolver(symbase.VSymbolResolver):
    pass

class MachoMixin:
    def platformGetSymbolResolver(self, filename, baseaddr):
        return MachoSymbolResolver(filename, baseaddr)

class DarwinMixin:

    def initMixin(self):
        self.tdict = {}

    def platformExec(self, cmdline):
        import mach
        pid = v_posix.PtraceMixin.platformExec(self, cmdline)
        self.task = mach.task_for_pid(pid)
        return pid

    def platformProcessEvent(self, status):
        """
        This is *extreemly* similar to the posix one, but I'm tired
        of trying to make the same code handle linux/bsd/mach.  They
        have subtle differences (particularly in threading).
        """

        if os.WIFEXITED(status):
            self.setMeta("ExitCode", os.WEXITSTATUS(status))
            self.fireNotifiers(vtrace.NOTIFY_EXIT)

        elif os.WIFSIGNALED(status):
            self.setMeta("ExitCode", os.WTERMSIG(status))
            self.fireNotifiers(vtrace.NOTIFY_EXIT)

        elif os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
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

        else:
            print "OMG WTF JUST HAPPENED??!?11/!?1?>!"

    def platformPs(self):
        import mach
        return mach.process_list()

    def platformGetFds(self):
        print "FIXME platformGetFds() no workie on darwin yet..."
        return []

    def platformGetMaps(self):
        return self.task.get_mmaps()

    def platformReadMemory(self, address, length):
        return self.task.vm_read(address, length)

    def platformWriteMemory(self, address, buffer):
        return self.task.vm_write(address, buffer)

    def currentMachThread(self):
        self.getThreads()
        return self.tdict[self.getMeta("ThreadId")]

    def platformGetRegs(self):
        """
        """
        thr = self.currentMachThread()
        regs = thr.get_state(self.thread_state)
        return regs + thr.get_state(self.debug_state)

    def platformSetRegs(self, regbuf):
        thr = self.currentMachThread()
        # XXX these 32 boundaries are wrong
        thr.set_state(self.thread_state, regbuf[:-32])
        thr.set_state(self.debug_state,  regbuf[-32:])

    def platformGetThreads(self):
        ret = {}
        self.tdict = {}
        spname = self.archGetSpName()
        for thread in self.task.threads():
            # We can't call platformGetRegs here... (loop, loop...)
            regbuf = thread.get_state(self.thread_state) + thread.get_state(self.debug_state)
            regdict = self.unpackRegisters(regbuf)
            sp = regdict.get(spname, 0)
            mapbase,maplen,mperm,mfile = self.getMap(sp)
            tid = mapbase + maplen # The TOP of the stack, so it doesn't grow down and change
            ret[tid] = tid
            self.tdict[tid] = thread
        self.setMeta("ThreadId", tid) #FIXME how can we know what thread caused an event?
        return ret

    def platformAttach(self, pid):
        import mach
        #FIXME setMeta("ExeName", stuff)
        self.task = mach.task_for_pid(pid)
        v_posix.PtraceMixin.platformAttach(self, pid)

class DarwinIntel32Registers:
    """
    Mixin for the register format of Darwin on Intel 32
    """
    thread_state = 1
    debug_state = 10

    def getRegisterFormat(self):
        return "24L"

    def getRegisterNames(self):
        return ("eax","ebx","ecx","edx","edi",
                "esi","ebp","esp","ss","eflags",
                "eip","cs","ds","es","fs","gs",
                "debug0","debug1","debug2","debug3",
                "debug4","debug5","debug6","debug7")

class DarwinPpc32Registers:
    """
    Mixin for the register format of Darwin on PPC 32
    """
    thread_state = 4
    debug_state = 11

    def getRegisterFormat(self):
        return "40L"

    def getRegisterNames(self):
        mylist = []
        for i in range(40):
            mylist.append("r%d" % i)
        return mylist

