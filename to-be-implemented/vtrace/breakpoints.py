
"""
Breakpoint Objects
"""

# Copyright (C) 2007 Invisigoth - See LICENSE file for details

import time

import vtrace

class Breakpoint:
    """
    Breakpoints in Vtrace are platform independant objects that
    use the underlying trace objects to get things like the
    program counter and the break instruction.  As long as
    platfforms are completely implemented, all breakpoint
    objects should be portable.


    """
    def __init__(self, address, enabled=True, expression=None):
        self.saved = None
        self.address = address
        self.enabled = enabled
        self.active = False
        self.id = -1
        self.vte = None
        self.bpcode = None
        self.bpcodeobj = None
        if expression:
            self.vte = vtrace.VtraceExpression(expression)

    def getAddress(self):
        """
        This will return the address for this breakpoint.  If the return'd
        address is None, this is a deferred breakpoint which needs to have
        resolveAddress() called to attempt to set the address.
        """
        return self.address

    def getId(self):
        return self.id

    def getName(self):
        if self.vte:
            return str(self.vte)
        return "0x%.8x" % self.address

    def __repr__(self):
        return "[%d] %s: %s" % (self.id, self.__class__.__name__, self.getName())

    def activate(self, trace):
        """
        Actually store off and replace memory for this process.  This
        is caried out by the trace object itself when it begins
        running or stops.  You probably never need to call this
        (see isEnabled() setEnabled() for boolean enable/disablle)
        """
        trace.requireAttached()
        if not self.active:
            if self.address != None:
                breakinst = trace.getBreakInstruction()
                self.saved = trace.readMemory(self.address, len(breakinst))
                trace.writeMemory(self.address, breakinst)
                self.active = True
        return self.active

    def deactivate(self, trace):
        """
        Repair the process for continued execution.  this does NOT
        make a breakpoint *inactive*, but removes it's "0xcc" from mem
        (see isEnabled() setEnabled() for boolean enable/dissable)
        """
        trace.requireAttached()
        if self.active:
            self.active = False
            trace.writeMemory(self.address, self.saved)
        return self.active

    def resolveAddress(self, trace):
        """
        Try to resolve the address for this break.  If this is a statically
        addressed break, just return the address.  If it has an "expression"
        use that to resolve the address...
        """
        if self.address == None and self.vte:
            self.address = self.vte.evaluate(trace,noraise=True)
        return self.address

    def isEnabled(self):
        """
        Is this breakpoint "enabled"?
        """
        return self.enabled

    def setEnabled(self, enabled=True):
        """
        Set this breakpoints "enabled" status
        """
        self.enabled = enabled

    def setBreakpointCode(self, pystr):
        """
        Use this method to set custom python code to run when this
        breakpoint gets hit.  The code will have the following objects
        mapped into it's namespace when run:
            trace - the tracer
            vtrace - the vtrace module
            bp - the breakpoint
        """
        self.bpcodeobj = None
        self.bpcode = pystr

    def getBreakpointCode(self):
        """
        Return the current python string that will be run when this break is hit.
        """
        return self.bpcode

    def notify(self, event, trace):
        """
        Breakpoints may also extend and implement "notify" which will be
        called whenever they are hit.  If you want to continue the ability
        for this breakpoint to have bpcode, you must call this method from
        your override.
        """
        if self.bpcode != None:
            if self.bpcodeobj == None:
                fname = "BP:%d (0x%.8x)" % (self.id, self.address)
                self.bpcodeobj = compile(self.bpcode, fname, "exec")

            d = {"vtrace":vtrace,"trace":trace,"bp":self}
            exec(self.bpcodeobj, d, d)

class TrackerBreak(Breakpoint):
    """
    A breakpoint which will record how many times it was hit
    (by the address it was at) as metadata for the tracer.
    """
    def notify(self, event, trace):
        tb = trace.getMeta("TrackerBreak", None)
        if tb == None:
            tb = {}
        trace.setMeta("TrackerBreak", tb)
        tb[self.address] = (tb.get(self.address,0) + 1)
        Breakpoint.notify(self, event, trace)

class OneTimeBreak(Breakpoint):
    """
    This type of breakpoint is exclusivly for marking
    and code-coverage stuff.  It removes itself.
    (most frequently used with a continued trace)
    """
    def notify(self, event, trace):
        trace.removeBreakpoint(self.id)
        Breakpoint.notify(self, event, trace)

class StopRunForeverBreak(Breakpoint):
    """
    This breakpoint will turn off RunForever mode
    on the tracer object when hit.  it's a good way
    to let things run on and on processing exceptions
    but stop when you get to this one thing.
    """
    def notify(self, event, trace):
        trace.setMode("RunForever", False)
        Breakpoint.notify(self, event, trace)

class StopAndRemoveBreak(Breakpoint):
    """
    When hit, take the tracer out of run-forever mode and
    remove this breakpoint.
    """
    def notify(self, event, trace):
        trace.setMode("RunForever", False)
        trace.removeBreakpoint(self.id)
        Breakpoint.notify(self, event, trace)

class CallBreak(Breakpoint):
    """
    A special breakpoint which will restore process
    state (registers in particular) when it gets hit.
    This is primarily used by the call method inside
    the trace object to restore original state
    after a successful "call" method call.

    Additionally, the endregs dict will be filled in
    with the regs at the time it was hit and kept until
    we get garbage collected...
    """
    def __init__(self, address, saved_regs):
        Breakpoint.__init__(self, address, True)
        self.endregs = None # Filled in when we get hit
        self.saved_regs = saved_regs
        self.onehitwonder = True

    def notify(self, event, trace):
        if self.onehitwonder:
            self.onehitwonder = False
            return
        self.endregs = trace.getRegisters()
        trace.removeBreakpoint(self.id)
        trace.setRegisters(self.saved_regs)
        trace.setMeta("PendingSignal", 0)

class SnapshotBreak(Breakpoint):
    """
    A special breakpoint type which will produce vtrace snapshots
    for the target process when hit.  The snapshots will be saved
    to a default name of <exename>-<timestamp>.vsnap.  This is not
    recommended for use in heavily hit breakpoints as taking a
    snapshot is processor intensive.
    """
    def notify(self, event, trace):
        exe = trace.getExe()
        snap = trace.takeSnapshot()
        snap.saveToFile("%s-%d.vsnap" % (exe,time.time()))
        Breakpoint.notify(self, event, trace)

