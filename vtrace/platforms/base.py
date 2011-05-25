"""
Tracer Platform Base
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import struct
import vtrace
import traceback
import inspect
import platform
from Queue import Queue
from threading import Thread,currentThread,Lock
import traceback

class BasePlatformMixin:
    """
    Mixin for all the platformDoFoo functions that throws an
    exception so you know your platform doesn't implement it.
    """

    def platformGetThreads(self):
        """
        Return a dictionary of <threadid>:<tinfo> pairs where tinfo is either
        the stack top, or the teb for win32
        """
        raise Exception("Platform must implement platformGetThreads()")

    def platformSelectThread(self, thrid):
        """
        Platform implementers are encouraged to use the metadata field "ThreadId"
        as the identifier (int) for which thread has "focus".  Additionally, the
        field "StoppedThreadId" should be used in instances (like win32) where you
        must specify the ORIGINALLY STOPPED thread-id in the continue.
        """
        self.setMeta("ThreadId",thrid)

    def platformKill(self):
        raise Exception("Platform must implement platformKill()")

    def platformExec(self, cmdline):
        """
        Platform exec will execute the process specified in cmdline
        and return the PID
        """
        raise Exception("Platmform must implement platformExec")

    def platformInjectSo(self, filename):
        raise Exception("Platform must implement injectso()")

    def platformGetFds(self):
        """
        Return what getFds() wants for this particular platform
        """
        raise Exception("Platform must implement platformGetFds()")

    def platformGetMaps(self):
        """
        Return a list of the memory maps where each element has
        the following structure:
        (address, length, perms, file="")
        NOTE: By Default this list is available as Trace.maps
        because the default implementation attempts to populate
        them on every break/stop/etc...
        """
        raise Exception("Platform must implement GetMaps")

    def platformPs(self):
        """
        Actually return a list of tuples in the format
        (pid, name) for this platform
        """
        raise Exception("Platform must implement Ps")

    def getBreakInstruction(self):
        """
        Give me the bytes for the "break" instruction
        for this architecture.
        """
        raise Exception("Architecture module must implement getBreakInstruction")

    def archAddWatchpoint(self, address):
        """
        Add a watchpoint for the given address.  Raise if the platform
        doesn't support, or too many are active...
        """
        raise Exception("Architecture doesn't implement watchpoints!")

    def archRemWatchpoint(self, address):
        raise Exception("Architecture doesn't implement watchpoints!")

    def archCheckWatchpoints(self):
        """
        If the current register state indicates that a watchpoint was hit, 
        return the address of the watchpoint and clear the event.  Otherwise
        return None
        """
        pass

    def archGetSpName(self):
        """
        Return the name of the stack pointer for this architecture
        """
        raise Exception("Architecture module must implement archGetSpName")

    def archGetPcName(self):
        """
        Return the name from the name of the register which represents
        the program counter for this architecture (ie. "eip" for intel)
        """
        raise Exception("Architecture module must implement archGetPcName")

    def getStackTrace(self):
        """
        Return a list of the stack frames for this process
        (currently Intel/ebp based only).  Each element of the
        "frames list" consists of another list which is (eip,ebp)
        """
        raise Exception("Platform must implement getStackTrace()")

    def getRegisterFormat(self):
        """
        Return a struct.unpack() style format string for
        parsing the bytes given back from PT_GETREGS so
        we can parse it into an array.
        """
        raise Exception("Platform must implement getRegisterFormat")

    def getRegisterNames(self):
        """
        Return a list of the register names which correspods
        (in order) with the format string specified for
        getRegisterFormat()
        """
        raise Exception("Platform must implement getRegisterNames")

    def getExe(self):
        """
        Get the full path to the main executable for this
        *attached* Trace
        """
        return self.getMeta("ExeName","Unknown")

    def platformAttach(self, pid):
        """
        Actually carry out attaching to a target process.  Like
        platformStepi this is expected to be ATOMIC and not return
        until a complete attach.
        """
        raise Exception("Platform must implement platformAttach()")

    def platformContinue(self):
        raise Exception("Platform must implement platformContinue()")

    def platformDetach(self):
        """
        Actually perform the detach for this type
        """
        raise Exception("Platform must implement platformDetach()")

    def platformStepi(self):
        """
        PlatformStepi should be ATOMIC, meaning it gets called, and
        by the time it returns, you're one step further.  This is completely
        regardless of blocking/nonblocking/whatever.
        """
        raise Exception("Platform must implement platformStepi!")

    def platformCall(self, address, args, convention=None):
        """
        Platform call takes an address, and an array of args
        (string types will be mapped and located for you)

        platformCall is expected to return a dicionary of the
        current register values at the point where the call
        has returned...
        """
        raise Exception("Platform must implement platformCall")

    def platformGetRegs(self):
        raise Exception("Platform must implement platformGetRegs!")

    def platformSetRegs(self, bytes):
        raise Exception("Platform must implement platformSetRegs!")

    def platformAllocateMemory(self, size, perms=vtrace.MM_RWX, suggestaddr=0):
        raise Exception("Plaform does not implement allocate memory")
        
    def platformReadMemory(self, address, size):
        raise Exception("Platform must implement platformReadMemory!")
        
    def platformWriteMemory(self, address, bytes):
        raise Exception("Platform must implement platformWriteMemory!")

    def platformWait(self):
        """
        Wait for something interesting to occur and return a
        *platform specific* representation of what happened.

        This will then be passed to the platformProcessEvent()
        method which will be responsible for doing things like
        firing notifiers.  Because the platformWait() method needs
        to be commonly ThreadWrapped and you can't fire notifiers
        from within a threadwrapped function...
        """
        raise Exception("Platform must implement platformWait!")

    def platformProcessEvent(self, event):
        """
        This method processes the event data provided by platformWait()

        This method is responsible for firing ALL notifiers *except*:

        vtrace.NOTIFY_CONTINUE - This is handled by the run api (and isn't the result of an event)
        """
        raise Exception("Platform must implement platformProcessEvent")

    def platformGetSymbolResolver(self, libname, address):
        """
        Platforms must return a class which inherits from the VSymbolResolver
        from vtrace.symbase.
        """
        raise Exception("Platform must implement platformGetSymbolResolver")

class TracerMethodProxy:
    def __init__(self, proxymeth, thread):
        self.thread = thread
        self.proxymeth = proxymeth

    def __call__(self, *args, **kwargs):
        if currentThread().__class__ == TracerThread:
            return self.proxymeth(*args, **kwargs)

        queue = Queue()
        self.thread.queue.put((self.proxymeth, args, kwargs, queue))
        ret = queue.get()

        if issubclass(ret.__class__, Exception):
            raise ret
        return ret

class TracerThread(Thread):
    """
    Ok... so here's the catch... most debug APIs do *not* allow
    one thread to do the attach and another to do continue and another
    to do wait... they just dont.  So there.  I have to make a thread
    per-tracer (on most platforms) and proxy requests (for *some* trace
    API methods) to it for actual execution.  SUCK!

    However, this lets async things like GUIs and threaded things like
    cobra not have to be aware of which one is allowed and not allowed
    to make particular calls and on what platforms...  YAY!
    """
    def __init__(self):
        Thread.__init__(self)
        self.queue = Queue()
        self.setDaemon(True)
        self.go = True
        self.start()

    def run(self):
        """
        Run in a circle getting requests from our queue and
        executing them based on the thread.
        """
        while self.go:
            try:
                meth, args, kwargs, queue = self.queue.get()
                try:
                    queue.put(meth(*args, **kwargs))
                except Exception,e:
                    queue.put(e)
                    if vtrace.verbose:
                        traceback.print_exc()
                    # this deadlocks ?!
                    #if vtrace.exc_handler:
                    #    vtrace.exc_handler(*sys.exc_info())
                    continue
            except:
                if vtrace.verbose:
                    traceback.print_exc()


class UtilMixin:
    """
    This is all the essentially internal methods that platform implementors
    may use and the guts use directly.
    """

    def _initLocals(self):
        """
        The routine to initialize a tracer's initial internal state.  This
        is used by the initial creation routines, AND on attaches/executes
        to re-fresh the state of the tracer.
        WARNING: This will erase all metadata/symbols (modes/notifiers are kept)
        """
        self.pid = 0 # Attached pid (also used to know if attached)
        self.exited = False
        self.breakpoints = {}
        self.watchpoints = {}
        self.bpid = 0
        self.bplock = Lock()
        self.deferredwatch = []
        self.deferred = []
        self.running = False
        self.attached = False
        # A cache for memory maps and fd listings
        self.mapcache = None
        self.threadcache = None
        self.fds = None
        self.signal_ignores = []

        # For all transient data (if notifiers want
        # to track stuff per-trace
        self.metadata = {}

        # Set up some globally expected metadata
        self.setMeta("PendingSignal", 0)
        self.setMeta("IgnoredSignals",[])
        self.setMeta("AutoContinue", False)
        self.setMeta("LibraryBases", {}) # name -> base address mappings for binaries
        self.setMeta("ThreadId", -1) # If you *can* have a thread id put it here
        arch = platform.machine()
        plat = platform.system()
        rel  = platform.release()
        #FIXME windows hack...
        if plat == "Windows" and arch == '':
            arch = "i386"
        self.setMeta("Architecture", arch)
        self.setMeta("Platform", plat)
        self.setMeta("Release", rel)

        # Use this if we are *expecting* a break
        # which is caused by us (so we remove the
        # SIGBREAK from pending_signal
        self.setMeta("ShouldBreak", False)

        self.resbynorm = {} # VSymbolResolvers, indexed by "normalized" libname
        self.resbyfile = {} # VSymbolResolvers indexed by file basename
        self.resbyaddr = [] # VSymbolResolver order'd by load base, decending...

    def nextBpId(self):
        self.bplock.acquire()
        x = self.bpid
        self.bpid += 1
        self.bplock.release()
        return x

    def unpackRegisters(self, regbuf):
        regs = {}
        siz = struct.calcsize(self.fmt)
        reglist = struct.unpack(self.fmt, regbuf[:siz])
        for i in range(len(reglist)):
            regs[self.regnames[i]] = reglist[i]
        return regs

    def packRegisters(self, regdict):
        p = []
        for n in self.regnames:
            p.append(regdict.get(n))
        return struct.pack(self.fmt, *p)

    def justAttached(self, pid):
        """
        platformAttach() function should call this
        immediately after a successful attach.  This does
        any necessary initialization for a tracer to be
        back in a clean state.
        """
        self.pid = pid
        self.attached = True
        self.breakpoints = {}
        self.setMeta("PendingSignal", 0)
        self.setMeta("PendingException", None)
        self.setMeta("ExitCode", 0)
        self.exited = False

    def getResolverForFile(self, filename):
        res = self.resbynorm.get(filename, None)
        if res: return res
        res = self.resbyfile.get(filename, None)
        if res: return res
        return None

    def steploop(self):
        """
        Continue stepi'ing in a loop until shouldRunAgain()
        returns false (like RunForever mode or something)
        """
        if self.getMode("NonBlocking", False):
            thr = Thread(target=self.doStepLoop, args=(until,))
            thr.setDaemon(True)
            thr.start()
        else:
            self.doStepLoop(until)

    def doStepLoop(self):
        go = True
        while go:
            self.stepi()
            go = self.shouldRunAgain()

    def _doRun(self):
        # Exists to avoid recursion from loop in doWait
        self.requireAttached()
        self.requireNotRunning()
        self.requireNotExited()

        self.fireNotifiers(vtrace.NOTIFY_CONTINUE)

        # Step past a breakpoint if we are on one.
        self._checkForBreak()
        # Throw down and activate breakpoints...
        self._throwdownBreaks()

        self.running = True
        # Syncregs must happen *after* notifiers for CONTINUE
        # and checkForBreak.
        self.syncRegs()
        self.platformContinue()
        self.setMeta("PendingSignal", 0)

    def wait(self):
        """
        Wait for the trace target to have
        something happen...   If the trace is in
        NonBlocking mode, this will fire a thread
        to wait for you and return control immediately.
        """
        if self.getMode("NonBlocking"):
            thr = Thread(target=self._doWait)
            thr.setDaemon(True)
            thr.start()
        else:
            self._doWait()

    def _doWait(self):
        doit = True
        while doit:
        # A wrapper method for  wait() and the wait thread to use
            event = self.platformWait()
            self.running = False
            self.platformProcessEvent(event)
            doit = self.shouldRunAgain()
            if doit:
                self._doRun()

    def _throwdownBreaks(self):
        """
        Run through the breakpoints and setup
        the ones that are enabled.
        """
        if self.getMode("FastBreak"):
            if self.fb_bp_done:
                return

        for wp in self.deferredwatch:
            addr = wp.resolveAddress(self)
            if addr != None:
                self.deferredwatch.remove(wp)
                self.watchpoints[addr] = wp
                self.archAddWatchpoint(addr)

        # Resolve deferred breaks
        for bp in self.deferred:
            addr = bp.resolveAddress(self)
            if addr != None:
                self.deferred.remove(bp)
                self.breakpoints[addr] = bp

        for bp in self.breakpoints.values():
            if bp.isEnabled():
                try:
                    bp.activate(self)
                except:
                    print "WARNING - bp at",hex(bp.address),"invalid, disabling"
                    bp.setEnabled(False)

        if self.getMode("FastBreak"):
            self.fb_bp_done = True

    def syncRegs(self):
        """
        Sync the reg-cache into the target process
        """
        if self.regcachedirty:
            buf = self.packRegisters(self.regcache)
            self.platformSetRegs(buf)
            self.regcachedirty = False
        self.regcache = None

    def cacheRegs(self):
        """
        Make sure the reg-cache is populated
        """
        if self.regcache == None:
            regbuf = self.platformGetRegs()
            self.regcache = self.unpackRegisters(regbuf)

    def _checkForBreak(self):
        """
        Check to see if we've landed on a breakpoint, and if so
        deactivate and step us past it.

        WARNING: Unfortunatly, cause this is used immidiatly before
        a call to run/wait, we must block briefly even for the GUI
        """
        bp = self.breakpoints.get(self.getProgramCounter(), None)
        if bp:
            if bp.active:
                bp.deactivate(self)
                orig = self.getMode("FastStep")
                self.setMode("FastStep", True)
                self.stepi()
                self.setMode("FastStep", orig)
                bp.activate(self)
                return True
            else:
                self.stepi()
        return False

    def shouldRunAgain(self):
        """
        A unified place for the test as to weather this trace
        should be told to run again after reaching some stopping
        condition.
        """
        if not self.attached:
            return False

        if self.exited:
            return False

        if self.getMode("RunForever"):
            return True

        if self.getMeta("AutoContinue"):
            return True

        return False

    def saveRegisters(self, newregs):
        """
        This is used mostly by setRegisters.  Use with CAUTION: you must
        specify ALL the register values perfectly!
        """
        mylist = [self.fmt,]
        for i in range(len(self.regnames)):
            mylist.append(newregs[self.regnames[i]])
        bytes = struct.pack(*mylist)
        self.platformSetRegs(bytes)

    def __repr__(self):
        run = "stopped"
        exe = "None"
        if self.isRunning():
            run = "running"
        elif self.exited:
            run = "exited"
        exe = self.getMeta("ExeName")
        return "<%s pid: %d, exe: %s, state: %s>" % (self.__class__.__name__, self.pid, exe, run)

    def initMode(self, name, value, descr):
        """
        Initialize a mode, this should ONLY be called
        during setup routines for the trace!  It determines
        the available mode setings.
        """
        self.modes[name] = bool(value)
        self.modedocs[name] = descr

    def release(self):
        """
        Do cleanup when we're done.  This is mostly necissary
        because of the thread proxy holding a reference to this
        tracer...  We need to let him die off and try to get
        garbage collected.
        """
        if self.thread:
            self.thread.go = False

    def __del__(self):
        print "WOOT"
        if self.attached:
            self.detach()

        for cls in inspect.getmro(self.__class__):
            if cls.__name__ == "Trace":
                continue

            if hasattr(cls, "finiMixin"):
                cls.finiMixin(self)

        if self.thread:
            self.thread.go = False


    def fireTracerThread(self):
        self.thread = TracerThread()

    def fireNotifiers(self, event):
        """
        Fire the registered notifiers for the NOTIFY_* event.
        """
        if currentThread().__class__ == TracerThread:
            raise Exception("ERROR: you can't fireNotifiers from *inside* the TracerThread")

        # Skip out on notifiers for NOTIFY_BREAK when in
        # FastBreak mode
        if self.getMode("FastBreak", False) and event == vtrace.NOTIFY_BREAK:
            return

        if self.getMode("FastStep", False) and event == vtrace.NOTIFY_STEP:
            return

        if event == vtrace.NOTIFY_SIGNAL:
            win32 = self.getMeta("Win32Event", None)
            if win32:
                code = win32["ExceptionCode"]
            else:
                code = self.getMeta("PendingSignal", 0)

            if code in self.getMeta("IgnoredSignals", []):
                if vtrace.verbose: print "Ignoring",code
                self.setMeta("AutoContinue", True)
                return

        alllist = self.getNotifiers(vtrace.NOTIFY_ALL)
        nlist = self.getNotifiers(event)

        trace = self
        # if the trace has a proxy it's notifiers
        # need that, cause we can't be pickled ;)
        if self.proxy:
            trace = self.proxy

        # The "NOTIFY_ALL" guys get priority
        for notifier in alllist:
            try:
                if notifier == self:
                    notifier.handleEvent(event,self)
                else:
                    notifier.handleEvent(event,trace)
            except:
                print "WARNING: Notifier exception for",repr(notifier)
                traceback.print_exc()

        for notifier in nlist:
            try:
                if notifier == self:
                    notifier.handleEvent(event,self)
                else:
                    notifier.handleEvent(event,trace)
            except:
                print "WARNING: Notifier exception for",repr(notifier)
                traceback.print_exc()

    def cleanupBreakpoints(self):
        self.fb_bp_done = False
        for bp in self.breakpoints.itervalues():
            # No harm in calling deactivate on
            # an inactive bp
            bp.deactivate(self)

    def checkWatchpoints(self):
        addr = self.archCheckWatchpoints()
        if not addr:
            return False
        wp = self.watchpoints.get(addr, None)
        if not wp:
            return False

        wp.notify(vtrace.NOTIFY_BREAK, self)
        self.fireNotifiers(vtrace.NOTIFY_BREAK)
        return True

    def getCurrentBreakpoint(self):
        """
        Return the current breakpoint otherwise None
        """
        # NOTE: Check breakpoints below can't use this cause
        # it comes before we've stepped back
        return self.breakpoints.get(self.getProgramCounter(), None)

    def checkBreakpoints(self):
        """
        This is mostly for systems (like linux) where you can't tell
        the difference between some SIGSTOP/SIGBREAK conditions and
        an actual breakpoint instruction.
        This method will return true if either the breakpoint
        subsystem or the sendBreak (via ShouldBreak meta) is true
        """
        if self.checkWatchpoints():
            return True

        pc = self.getProgramCounter()
        bi = self.getBreakInstruction()
        bl = pc - len(bi)
        bp = self.breakpoints.get(bl, None)

        if bp:
            addr = bp.getAddress()
            # Step back one instruction to account break
            self.setProgramCounter(addr)
            self.fireNotifiers(vtrace.NOTIFY_BREAK)
            try:
                bp.notify(vtrace.NOTIFY_BREAK, self)
            except Exception, msg:
                print "Breakpoint Exception 0x%.8x : %s" % (addr,msg)
            return True

        elif self.getMeta("ShouldBreak"):
            self.setMeta("ShouldBreak", False)
            self.fireNotifiers(vtrace.NOTIFY_BREAK)
            return True

        return False

    def notify(self, event, trace):
        """
        We are frequently a notifier for ourselves, so we can do things
        like handle events on attach and on break in a unified fashion.
        """
        self.threadcache = None
        self.mapcache = None
        self.fds = None
        self.running = False

        if event in self.auto_continue:
            self.setMeta("AutoContinue", True)
        else:
            self.setMeta("AutoContinue", False)

        if event == vtrace.NOTIFY_ATTACH:
            pass

        elif event == vtrace.NOTIFY_DETACH:
            self.cleanupBreakpoints()

        elif event == vtrace.NOTIFY_EXIT:
            self.setMode("RunForever", False)
            self.exited = True
            self.attached = False

        elif event == vtrace.NOTIFY_CONTINUE:
            pass

        elif event == vtrace.NOTIFY_LOAD_LIBRARY:
            self.cleanupBreakpoints()

        else:
            if not self.getMode("FastBreak"):
                self.cleanupBreakpoints()


    def addLibraryBase(self, libname, address):
        """
        This should be used *at load time* to setup the library
        event metadata.  This will also instantiate a VSymbolResolver
        for this platform and setup the internal structures as necissary

        This returns True/False for whether or not the library is
        going to be parsed (False on duplicate or non-file).

        This *must* be called from a context where it's safe to
        fire notifiers, because it will fire a notifier to alert
        about a LOAD_LIBRARY. (This means *not* from inside another
        notifer)
        """
        basename = os.path.basename(libname)

        self.setMeta("LatestLibrary", None)
        self.setMeta("LatestLibraryNorm", None)

        # Only actually do library work
        if (os.path.exists(libname) and
            not self.getMeta("LibraryBases").has_key(basename)):

            resolver = self.platformGetSymbolResolver(libname, address)
            self.resbynorm[resolver.normname] = resolver
            self.resbyfile[resolver.basename] = resolver
            self.getMeta("LibraryBases")[resolver.normname] = address

            self.setMeta("LatestLibrary", libname)
            self.setMeta("LatestLibraryNorm", resolver.normname)

            # We keep a descending order'd list of the resolver's base's so we
            # Can find the best resolver for an address quickly
            #FIXME move this to inside the resolvers
            index = 0
            if len(self.resbyaddr) > 0:
                index = None
                for i in range(len(self.resbyaddr)):
                    if resolver.loadbase > self.resbyaddr[i].loadbase:
                        index = i
                        break
                if index != None:
                    self.resbyaddr.insert(index, resolver)
                else:
                    self.resbyaddr.append(resolver)
            else:
                self.resbyaddr.append(resolver)

        self.fireNotifiers(vtrace.NOTIFY_LOAD_LIBRARY)
        return True

    def threadWrap(self, name, meth):
        """
        Cause the method (given in value) to be wrapped
        by a single thread for carying out.
        (which allows us to only synchronize what *needs* to
        synchronized...)
        """
        wrapmeth = TracerMethodProxy(meth, self.thread)
        setattr(self, name, wrapmeth)

