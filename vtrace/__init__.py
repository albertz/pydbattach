"""
Vtrace Debugger Framework

Vtrace is a *mostly* native python debugging framework which
can be used to quickly write programatic debuggers and research
tools.

I'm not known for writting great docs...  but the code should
be pretty straight forward...

This has been in use for over 2 years privately, but is nowhere
*near* free of bugs...  idiosyncracies abound.

==== Werd =====================================================

Blah blah blah... many more docs to come.

Brought to you by kenshoto.  e-mail invisigoth.

Greetz:
	h1kari - eeeeeooorrrmmm  CHKCHKCHKCHKCHKCHKCHK
	Ghetto - wizoo... to the tizoot.
	atlas - *whew* finally...  no more teasing...
	beatle/dnm - come out and play yo!
	The Kenshoto Gophers.
	Blackhats Everywhere.

"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import sys
import code
import copy
import time
import types
import struct
import getopt
import signal
import inspect
import platform
import traceback

import cPickle as pickle

import cobra
import vstruct

remote = None       # If set, we're a vtrace client (set to serverhost)
cobra_daemon = None
port = 0x5656
symbolcache = {} # A list of vtrace symbols key'd by filename
verbose = False

# Order must match format junk
# NOTIFY_ALL is kinda special, if you registerNotifier
# with it, you get ALL notifications.
NOTIFY_ALL = 0          # Get all notifications
NOTIFY_SIGNAL = 1       # Callback on signal/exception
NOTIFY_BREAK = 2        # Callback on breakpoint / sigtrap
NOTIFY_STEP = 3         # Callback on singlestep complete
NOTIFY_SYSCALL = 4      # Callback on syscall (linux only for now)
NOTIFY_CONTINUE = 5     # Callback on continue (not done for step)
NOTIFY_EXIT = 6         # Callback on process exit
NOTIFY_ATTACH = 7       # Callback on successful attach
NOTIFY_DETACH = 8       # Callback on impending process detach       
# The following notifiers are *only* available on some platforms
# (and may be kinda faked out ala library load events on posix)
NOTIFY_LOAD_LIBRARY = 9
NOTIFY_UNLOAD_LIBRARY = 10 
NOTIFY_CREATE_THREAD = 11
NOTIFY_EXIT_THREAD = 12
NOTIFY_DEBUG_PRINT = 13 # Some platforms support this (win32).
NOTIFY_MAX = 20

# File Descriptor / Handle Types
FD_UNKNOWN = 0 # Unknown or we don't have a type for it
FD_FILE = 1
FD_SOCKET = 2
FD_PIPE = 3
FD_LOCK = 4   # Win32 Mutant/Lock/Semaphore
FD_EVENT = 5  # Win32 Event/KeyedEvent
FD_THREAD = 6 # Win32 Thread
FD_REGKEY = 7 # Win32 Registry Key

# Memory Map Permission Flags
MM_READ = 0x4
MM_WRITE = 0x2
MM_EXEC = 0x1
MM_SHARED = 0x08

MM_RWX = (MM_READ | MM_WRITE | MM_EXEC)

# Vtrace Symbol Types
SYM_MISC = -1
SYM_GLOBAL = 0 # Global (mostly vars)
SYM_LOCAL = 1 # Locals
SYM_FUNCTION = 2 # Functions
SYM_SECTION = 3 # Binary section
SYM_META = 4 # Info that we enumerate

# Vtrace Symbol Offsets
VSYM_NAME = 0
VSYM_ADDR = 1
VSYM_SIZE = 2
VSYM_TYPE = 3
VSYM_FILE = 4

#from vtrace.rmi import *
#from vtrace.notifiers import *
#from vtrace.breakpoints import *
#from vtrace.util import *

from vtrace.rmi import *
from vtrace.notifiers import *
from vtrace.breakpoints import *
import vtrace.util as v_util
import vtrace.platforms.base as v_base

class PlatformException(Exception):
	"""
	A universal way to represent a failure in the
	platform layer for this tracer.  platformFoo methods
	should raise this rather than allowing their platform
	specific exception types (which don't likely pickle, or
	are not cross platform)
	"""
	pass

class AccessViolation(Exception):
	"""
	An exception which is raised on bad-touch to memory
	"""
	def __init__(self, va, perm=0):
		self.va = va
		self.perm = perm
		Exception.__init__(self, "AccessViolation at 0x%.8x (%d)" % (va, perm))

class Trace(Notifier):
	"""
	The main tracer object.  A trace instance is dynamically generated using
	this and *many* potential mixin classes.  However, API users should *not*
	worry about the methods that come from the mixins...  Everything that is
	*meant* to be used from the API is contained and documented here.
	"""
	def __init__(self):
		# For the crazy thread-call-proxy-thing
		# (must come first for __getattribute__
		self.requires_thread = {}
		self.proxymeth = None # FIXME hack for now...
		self.fireTracerThread()
		# The universal place for all modes
		# that might be platform dependant...
		self.modes = {}
		self.modedocs = {}
		self.notifiers = {}

		self.initMode("RunForever", False, "Run until RunForever = False")
		self.initMode("NonBlocking", False, "A call to wait() fires a thread to wait *for* you")
		self.initMode("ThreadProxy", True, "Proxy necissary requests through a single thread (can deadlock...)")
		self.initMode("FastBreak", False, "Do *NOT* add/remove breakpoints per-run, but leave them there once active")
		self.initMode("SingleStep", False, "All calls to run() actually just step.  This allows RunForever + SingleStep to step forever ;)")
		self.initMode("FastStep", False, "All stepi() will NOT generate a step event")

		self.fmt = self.getRegisterFormat()
		self.regnames = self.getRegisterNames()
		self.regcache = None
		self.regcachedirty = False
		self.fb_bp_done = False # A little hack for FastBreak mode


		# Set if we're a server and this trace is proxied
		self.proxy = None

		Notifier.__init__(self)

		# We'll just use our own notify interface to catch some stuff
		# (which also more-or-less guarentees we'll be first notified for these)
		self.registerNotifier(NOTIFY_ALL, self)

		# Add event numbers to here for auto-continue
		self.auto_continue = [NOTIFY_LOAD_LIBRARY, NOTIFY_CREATE_THREAD, NOTIFY_UNLOAD_LIBRARY, NOTIFY_EXIT_THREAD, NOTIFY_DEBUG_PRINT]

		self._initLocals()

	def execute(self, cmdline):
		"""
		Start a new process and debug it
		"""
		if self.isAttached():
			raise Exception("ERROR - Tracer must first be detached before you can execute()")

		pid = self.platformExec(cmdline)
		self.justAttached(pid)
		self.wait()

	def addIgnoreSignal(self, code, address=0):
		"""
		By adding an IgnoreSignal you tell the tracer object to
		supress the notification of a particular type of signal.
		In POSIX, these are regular signals, in Win32, these
		are exception codes.  This is mostly useful in RunForever
		mode because you still need the process to begin running again.
		(these may be viewed/modified by the metadata key "IgnoredSignals")
		FIXME: make address do something.
		"""
		self.getMeta("IgnoredSignals").append(code)

	def delIgnoreSignal(self, code, address=0):
		"""
		See addIgnoreSignal for a description of signal ignoring.
		This removes an ignored signal and re-enables it's delivery.
		"""
		self.getMeta("IgnoredSignals").remove(code)

	def attach(self, pid):
		"""
		Attach to a new process ID.
		"""
		if self.isAttached():
			self.detach()
	
		try:
			self.platformAttach(pid)
			self.justAttached(pid)
			self.wait()
		except Exception, msg:
			raise PlatformException(str(msg))

	def stepi(self):
		"""
		Single step the target process ONE instruction (and do
		NOT activate breakpoints for the one step). Also, we 
		don't deliver pending signals for the single step...
		Use the mode FastStep to allow/supress notifier callbacks on step
		"""
		self.requireAttached()
		self.syncRegs()
		self.platformStepi()
		event = self.platformWait()
		self.platformProcessEvent(event)

	def run(self, until=None):
		"""
		Allow the traced target to continue execution.  (Depending on the mode
		"Blocking" this will either block until an event, or return immediately)
		Additionally, the argument until may be used to cause execution to continue
		until the specified address is reached (internally uses and removes a breakpoint).
		"""
		if self.getMode("SingleStep", False):
			self.steploop()
		else:
			if until != None:
				self.setMode("RunForever", True)
				self.addBreakpoint(StopAndRemoveBreak(until))
			self._doRun()
			self.wait()

	def kill(self):
		"""
		Kill the target process for this trace (will result in process
		exit and fire appropriate notifiers)
		"""
		self.requireAttached()
		self.requireNotExited()
		# kill may require that we continue
		# the process before it gets processed,
		# so we'll try to run the process until it
		# exits due to the kill
		self.setMode("RunForever", True) # Forever actually means util exit
		if self.isRunning():
			self.platformKill()
		else:
			self.platformKill()
			self.run()

	def detach(self):
		"""
		Detach from the currently attached process.
		"""
		self.requireAttached()
		self.requireNotRunning()
		self.fireNotifiers(NOTIFY_DETACH)
		self.syncRegs()
		self.platformDetach()
		self.attached = False
		self.pid = 0
		self.mapcache = None

	def getPid(self):
		"""
		Return the pid for this Trace
		"""
		return self.pid

	def getNormalizedLibNames(self):
		"""
		Symbols are stored internally based off of
		"normalized" library names.  This method returns
		the list of normalized names for the loaded libraries.

		(probably only useful for writting symbol browsers...)
		"""
		return self.resbynorm.keys()

	def getSymsForFile(self, libname):
		"""
		Return the entire symbol list for the specified
		filename.
		"""
		res = self.getResolverForFile(libname)
		if not res:
			return []
		return res.symList()

	def getSymByName(self, name, libname):
		"""
		Return a VSymbol() object for the given name
		from the given binary file.
		
		See the docs on VSymbols() for details (in vtrace.symbase)
		"""
		res = self.getResolverForFile(libname)
		if not res:
			return None
		return res.symByName(name)

	def getSymByAddr(self, addr):
		"""
		Return the *closest* VSymbol prior to this but ONLY
		from within the symbol resolver for the filename
		which is mapped at that address.

		See the docs on VSymbols() for details (in vtrace.symbase)
		"""
		map = self.getMap(addr)
		if map == None:
			return None
		fname = map[3]
		if not fname:
			return None
		res = self.getResolverForFile(os.path.basename(fname))
		if not res:
			return None
		return res.symByAddr(addr)


	def getRegisterByName(self, name):
		"""
		Return an int value for the specified
		register by name.
		"""
		self.requireAttached()
		self.cacheRegs()
		val = self.regcache.get(name, None)
		if val == None:
			raise Exception("ERROR - Unknown register name %s" % name)
		return val

	def setRegisterByName(self, name, value):
		"""
		Set a target register by name to the int()
		(or possibly long) value  specified.
		"""
		self.cacheRegs()
		if not self.regcache.has_key(name):
			raise Exception("Unknown Register %s" % name)
		self.regcache[name] = long(value)
		self.regcachedirty = True

	def getRegisters(self):
		"""
		Return a dict entry of the "user" registers for this process.
		"""
		self.requireAttached()
		self.cacheRegs()
		return dict(self.regcache)

	def setRegisters(self, newregs):
		"""
		Set any registers specified in the dict newregs to their int values.
		(only the specified registers are effected)
		"""
		self.requireAttached()
		for name,val in newregs.items():
			self.setRegisterByName(name, val)

	def searchMemory(self, needle):
		"""
		A quick cheater way to searchMemoryRange() for each
		of the current memory maps.
		"""
		results = []
		for map in self.getMaps():
			# On most platforms, memory you can't
			# read is in kernel space, and you can't
			# read it with a debugger either ;)
			if not map[2] | MM_READ:
				continue
			try:
				results.extend(self.searchMemoryRange(needle, map[0],map[1]))
			except:
				pass # Some platforms dont let debuggers read non-readable mem
		return results

	def searchMemoryRange(self, needle, address, size):
		"""
		Search the specified memory range (address -> size)
		for the string needle.   Return a list of addresses
		where the match occurs.
		"""
		results = []
		memory = self.readMemory(address, size)
		offset = 0
		while offset < size:
			loc = memory.find(needle, offset)
			if loc == -1: # No more to be found ;)
				break
			results.append(address+loc)
			offset = loc+1 # Skip one past our matcher

		return results

	def allocateMemory(self, size, perms=MM_RWX, suggestaddr=0):
		"""
		Allocate a chunk of memory inside the target process' address
		space.  Memory wil be mapped rwx unless otherwise specified with
		perms=MM_FOO values. Optionally you may *suggest* an address
		to the allocator, but there is no guarentee.  Returns the mapped
		memory address.
		"""
		self.requireAttached()
		self.requireNotRunning()
		return self.platformAllocateMemory(size, perms=perms, suggestaddr=suggestaddr)

	def readMemory(self, address, size):
		"""
		Read memory from address.  Areas that are NOT valid memory will be read
		back as \x00s (this probably goes in a mixin soon)
		"""
		self.requireAttached()
		return self.platformReadMemory(long(address), long(size))

	def readMemoryFormat(self, address, fmt):
		"""
		This works much like python's struct package, only it doesn't
		suck. Seriously, fix that nonsense pydevs!
		"""
		size = struct.calcsize(fmt)
		bytes = self.readMemory(address, size)
		return struct.unpack(fmt, bytes)

	def writeMemory(self, address, bytes):
		"""
		Write the given bytes to the address in the current trace.
		"""
		self.requireAttached()
		self.platformWriteMemory(long(address), bytes)

	def writeMemoryFormat(self, address, fmt, *args):
		buf = struct.pack(fmt, *args)
		self.writeMemory(address, buf)

	def setMeta(self, name, value):
		"""
		Set some metadata.  Metadata is a clean way for
		arbitrary trace consumers (and notifiers) to present
		and track additional information in trace objects.

		Any modules which use this *should* initialize them
		on attach (so when they get re-used they're clean)

		Some examples of metadata used:
		ShouldBreak - We're expecting a non-signal related break
		ExitCode - The int() exit code  (if exited)
		PendingSignal - Used on posix systems
		PendingException - Mostly for win32 for now

		"""
		self.metadata[name] = value

	def getMeta(self, name, default=None):
		"""
		Get some metadata.  Metadata is a clean way for
		arbitrary trace consumers (and notifiers) to present
		and track additional information in trace objects.

		If you specify a default and the key doesn't exist, not
		not only will the default be returned, but the key will
		be set to the default specified.
		"""
		if default:
			if not self.metadata.has_key(name):
				self.metadata[name] = default
		return self.metadata.get(name, None)

	def hasMeta(self, name):
		"""
		Check to see if a metadata key exists... Mostly un-necissary
		as getMeta() with a default will set the key to the default
		if non-existant.
		"""
		return self.metadata.has_key(name)

	def getMode(self, name, default=False):
		"""
		Get the value for a mode setting allowing
		for a clean default...
		"""
		return self.modes.get(name, default)

	def setMode(self, name, value):
		"""
		Set a mode setting...  This is ONLY valid
		if that mode has been iniitialized with
		initMode(name, value).  Otherwise, it's an
		unsupported mode for this platform ;)  cute huh?
		This way, platform sections can cleanly setmodes
		and such.
		"""
		if not self.modes.has_key(name):
			raise Exception("Mode %s not supported on this platform" % name)
		self.modes[name] = bool(value)

	def injectso(self, filename):
		"""
		Inject a shared object into the target of the trace.  So, on windows
		this is easy with InjectDll and on *nix... it's.. fugly...
		"""
		self.platformInjectSo(filename)

	def ps(self):
		"""
		Return a list of proccesses which are currently running on the
		system.
		(pid, name)
		"""
		return self.platformPs()

	def addWatchpoint(self, watchpoint):
		"""
		Add a "break on access" watch-point provided that the hardware
		has support and sufficient resources are aviailable.  The "watchpoint"
		argument must extend the vtrace.watchpoints.Watchpoint object and will
		have it's "notify" method called when hit...  This method returns
		the ID assigned to the watch point.
		"""
		# Watchpoints are handled by the breakpoint subsystem...
		watchpoint.id = self.nextBpId()
		addr = watchpoint.resolveAddress(self)
		if addr == None:
			self.deferredwatch.append(watchpoint)
		else:
			self.archAddWatchpoint(addr)
			self.watchpoints[addr] = watchpoint

	def removeWatchpoint(self, id):
		"""
		Remove a previously added watchpoint by id.
		"""
		for wp in self.deferredwatch:
			if wp.getId() == id:
				self.deferredwatch.remove(wp)
				return

		for addr,wp in self.watchpoints.items():
			if wp.getId() == id:
				self.watchpoints.pop(addr)
				self.archRemWatchpoint(addr)
				return

	def addBreakpoint(self, breakpoint):
		"""
		Add a breakpoint to the trace.  The "breakpoint" argument
		is a vtrace Breakpoint object or something that extends it.

		To add a basic breakpoint use trace.addBreakpoint(vtrace.Breakpoint(address))
		NOTE: expression breakpoints do *not* get evaluated in fastbreak mode

		This will return the internal ID given to the new breakpoint
		"""
		breakpoint.id = self.nextBpId()
		addr = breakpoint.resolveAddress(self)
		if addr == None:
			self.deferred.append(breakpoint)
		else:
			if self.breakpoints.has_key(addr):
				raise Exception("ERROR: Duplicate break for address 0x%.8x" % addr)
			self.breakpoints[addr] = breakpoint

		return breakpoint.id
			
	def removeBreakpoint(self, id):
		"""
		Remove the breakpoint with the specified ID
		"""
		self.requireAttached()
		for bp in self.deferred:
			if bp.getId() == id:
				bp.deactivate(self)
				self.deferred.remove(bp)
				return

		for addr,bp in self.breakpoints.items():
			if bp.getId() == id:
				bp.deactivate(self)
				self.breakpoints.pop(addr, None)

	def getBreakpoint(self,id):
		"""
		Return a reference to the breakpoint with the requested ID.

		NOTE: NEVER set locals or use things like setBreakpointCode()
		method on return'd breakpoint objects as they may be remote
		and would then be *coppies* of the bp objects. (use the trace's
		setBreakpointCode() instead).
		"""
		for bp in self.deferred:
			if bp.getId() == id:
				bp.bpcodeobj = None
				return bp
		for bp in self.breakpoints.values():
			if bp.getId() == id:
				bp.bpcodeobj = None
				return bp
		return None

	def getBreakpoints(self):
		"""
		Return a list of the current breakpoints.
		"""
		ret = self.breakpoints.values() + self.deferred
		for bp in ret:
			bp.bpcodeobj = None
		return ret

	def getBreakpointEnabled(self, bpid):
		"""
		An accessor method for returning if a breakpoint is
		currently enabled.
		NOTE: code which wants to be remote-safe should use this
		"""
		bp = self.getBreakpoint(bpid)
		if bp == None:
			raise Exception("Breakpoint %d Not Found" % bpid)
		return bp.isEnabled()

	def setBreakpointEnabled(self, bpid, enabled=True):
		"""
		An accessor method for setting a breakpoint enabled/disabled.

		NOTE: code which wants to be remote-safe should use this
		"""
		bp = self.getBreakpoint(bpid)
		if bp == None:
			raise Exception("Breakpoint %d Not Found" % bpid)
		return bp.setEnabled(enabled)

	def setBreakpointCode(self, bpid, pystr):
		"""
		Because breakpoints are potentially on the remote debugger
		and code is not pickleable in python, special access methods
		which takes strings of python code are necissary for the
		vdb interface to quick script breakpoint code.  Use this method
		to set the python code for this breakpoint.
		"""
		self.getBreakpoint(bpid).setBreakpointCode(pystr)

	def getBreakpointCode(self, bpid):
		"""
		Return the python string of user specified code that will run
		when this breakpoint is hit.
		"""
		return self.getBreakpoint(bpid).getBreakpointCode()

	def call(self, address, args, convention=None):
		"""
		Setup the "stack" and call the target address with the following
		arguments.  If the argument is a string or a buffer, copy that into
		memory and hand in the argument.

		The current state of ALL registers are returned as a dictionary at the
		end of the call...

		Additionally, a "convention" string may be specified that the underlying
		platform may be able to interpret...
		"""
		return self.platformCall(address, args, convention)

	def registerNotifier(self, event, notifier):
		"""
		Register a notifier who will be called for various
		events.  See NOTIFY_* constants for handler hooks.
		"""
		nlist = self.notifiers.get(event,None)
		if nlist:
			nlist.append(notifier)
		else:
			nlist = []
			nlist.append(notifier)
			self.notifiers[event] = nlist

	def deregisterNotifier(self, event, notifier):
		nlist = self.notifiers.get(event, [])
		if notifier in nlist:
			nlist.remove(notifier)

	def getNotifiers(self, event):
		return self.notifiers.get(event, [])

	def requireNotExited(self):
		if self.exited:
			raise Exception("ERROR - Request invalid for trace which exited")

	def requireNotRunning(self):
		"""
		Just a quick method to throw an error if the
		tracer is already running...
		"""
		if self.isRunning():
			raise Exception("ERROR - Request invalid for running trace")

	def requireAttached(self):
		"""
		A utility method for other methods to use in order
		to require being attached
		"""
		if not self.attached:
			raise Exception("ERROR - Must be attached to a process")

	def getFds(self):
		"""
		Get a list of (fd,type,bestname) pairs.  This is MOSTLY useful
		for HUMON consumtion...  or giving HUMONs consumption...
		"""
		self.requireAttached()
		if not self.fds:
			self.fds = self.platformGetFds()
		return self.fds

	def getMaps(self):
		"""
		Return a list of the currently mapped memory for the target
		process.  This is acomplished by calling the platform's
		platformGetMaps() mixin method.  This will also cache the
		results until CONTINUE.  The format is (addr,len,perms,file).
		"""
		if not self.mapcache:
			self.mapcache = self.platformGetMaps()
		return self.mapcache

	def getMap(self, address):
		"""
		Get the mmap for the target address from the current Trace.
		This will return None if the address is not in any map
		(this can also be used as a cheater isMemoryValid() type routine)
		"""
		address = long(address)
		maps = self.getMaps()
		for map in maps:
			base = map[0]
			mlen = map[1]
			if address >= base and address < (base+mlen):
				return map

		return None

	def getMapBase(self, filename):
		"""
		Return the base map address for the
		memory map which is backed by the given
		file name.
		"""
		maps = self.getMaps()
		for map in maps:
			if map[3] == filename:
				return map[0]

		raise Exception("ERROR - Unknown map name %s\n" % filename)

	def isAttached(self):
		"""
		Return boolean true/false for weather or not this trace is
		currently attached to a process.
		"""
		return self.attached

	def isRunning(self):
		"""
		Return true or false if this trace's target process is "running".
		"""
		return self.running

	def enableAutoContinue(self, event):
		"""
		Put the tracer object in to AutoContinue mode
		for the specified event.  To make all events
		continue running see RunForever mode in setMode().
		"""
		if event not in self.auto_continue:
			self.auto_continue.append(event)

	def disableAutoContinue(self, event):
		"""
		Disable Auto Continue for the specified
		event.
		"""
		if event in self.auto_continue:
			self.auto_continue.remove(event)

	def parseExpression(self, expression, noraise=False):
		"""
		This is a convenience wrapper for the VtraceExpression
		object.  It returns the current evaluation of the expression
		right now.  This can raise if invalid syntax or unknown symbols
		are used.

		See the docs for the VtraceExpression object for details on the
		expression syntax...
		"""
		e = VtraceExpression(expression)
		return e.evaluate(self, noraise=noraise)

	def sendBreak(self):
		"""
		Send an asynchronous break signal to the target process.
		This is only valid if the target is actually running...
		"""
		self.requireAttached()
		if not self.isRunning():
			raise Exception("Why sending a break when not running?!?!")
		self.setMode("RunForever", False)
		self.setMode("FastBreak", False)
		self.setMeta("ShouldBreak", True)
		self.platformSendBreak()
		# If we're non-blocking, we gotta wait...
		if self.getMode("NonBlocking", True):
			while self.isRunning():
				time.sleep(0.01)

	def getProgramCounter(self):
		"""
		An architecture independant way to get the value for the
		program counter on this platform (ie "eip" for all you 
		intel only neordz)  Breakpoint subsystem uses this to be
		independant on my dreamcast...
		"""
		self.requireAttached()
		name = self.archGetPcName()
		return self.getRegisterByName(name)

	def setProgramCounter(self, value):
		"""
		Set the current instruction pointer.  See getProgramCounter()
		for why this exists.
		"""
		self.requireAttached()
		name = self.archGetPcName()
		return self.setRegisterByName(name,value)

	def getStackCounter(self):
		"""
		An architecture independant way to get the current stack pointer
		value
		"""
		self.requireAttached()
		name = self.archGetSpName()
		return self.getRegisterByName(name)

	def setStackCounter(self, value):
		"""
		An architecture independant way to set the current stack pointer
		value
		"""
		self.requireAttached()
		name = self.archGetSpName()
		return self.setRegisterByName(name, value)

	def getStackTrace(self):
		"""
		Returns a list of (instruction pointer, stack frame) tuples.
		If stack tracing results in an error, the error entry will
		be (-1,-1).  Otherwise most platforms end up with 0,0 as
		the top stack frame
		"""
		#FIXME this should be a platform call!
		raise Exception("ERROR - Platform must implement this")

	def getThreads(self):
		"""
		Get a dictionary of <threadid>:<tinfo> pairs where
		tinfo is platform dependant, but is tyically either
		the top of the stack for that thread, or the TEB on
		win32
		"""
		if not self.threadcache:
			self.threadcache = self.platformGetThreads()
		return self.threadcache

	def selectThread(self, threadid):
		"""
		Set the "current thread" context to the given thread id.
		(For example stack traces and register values will depend
		on the current thread context).  By default the thread
		responsible for an "interesting event" is selected.
		"""
		if threadid not in self.getThreads():
			raise Exception("ERROR: Invalid threadid chosen: %d" % threadid)
		self.syncRegs()
		self.platformSelectThread(threadid)
		self.setMeta("ThreadId", threadid)

	def takeSnapshot(self):
		"""
		Take a snapshot of the process from the current state and return
		a reference to a tracer which wraps a "snapshot" or "core file".
		"""
		sd = dict()
		orig_thread = self.getMeta("ThreadId")

		regs = dict()
		stacktrace = dict()

		for thrid,tdata in self.getThreads().items():
			self.selectThread(thrid)
			regs[thrid] = self.getRegisters()
			try:
				stacktrace[thrid] = self.getStackTrace()
			except Exception, msg:
				print >> sys.stderr, "WARNING: Failed t get stack trace for thread 0x%.8x" % thrid

		mem = dict()
		for base,size,perms,fname in self.getMaps():
			try:
				mem[base] = self.readMemory(base, size)
			except Exception, msg:
				print >> sys.stderr, "WARNING: Can't snapshot memmap at 0x%.8x (%s)" % (base,msg)

		# If the contents here change, change the version...
		sd['version'] = 1
		sd['threads'] = self.getThreads()
		sd['regs'] = regs
		sd['maps'] = self.getMaps()
		sd['mem'] = mem
		sd['meta'] = copy.deepcopy(self.metadata)
		sd['pcname'] = self.archGetPcName()
		sd['spname'] = self.archGetSpName()
		sd['stacktrace'] = stacktrace
		sd['exe'] = self.getExe()
		sd['fds'] = self.getFds()

		if orig_thread != -1:
			self.selectThread(orig_thread)

		return TraceSnapshot(snapdict=sd)

	def getStruct(self, sname, address):
		"""
		Retrieve a vstruct structure populated with memory from
		the specified address.  Returns a standard vstruct object.
		"""
		cls = vstruct.getStructClass(sname)
		size = vstruct.calcsize(cls)
		bytes = self.readMemory(address, size)
		return cls(bytes)

class TraceSnapshot(Trace, v_base.BasePlatformMixin, v_base.UtilMixin):
	"""
	A tracer snapshot is similar to a traditional "core file" except that
	you may also have memory only snapshots that are never written to disk.

	TraceSnapshots allow you to take a picture of a process from a given point
	in it's execution and manipulate/test from there or save it to disk for later
	analysis...
	"""
	def __init__(self, filename=None, snapdict=None):
		Trace.__init__(self)
		if filename == None and snapdict == None:
			raise Exception("ERROR: TraceSnapshot needs either filename or snapdict!")

		if filename:
			sfile = file(filename, "rb")
			snapdict = pickle.load(sfile)

		self.s_snapdict = snapdict

		# a seperate parser for each version...
		if snapdict['version'] == 1:
			self.s_version = snapdict['version']
			self.s_threads = snapdict['threads']
			self.s_regs = snapdict['regs']
			self.s_maps = snapdict['maps']
			self.s_mem = snapdict['mem']
			self.metadata = snapdict['meta']
			self.s_spname = snapdict['spname']
			self.s_pcname = snapdict['pcname']
			self.s_stacktrace = snapdict['stacktrace']
			self.s_exe = snapdict['exe']
			self.s_fds = snapdict['fds']
		else:
			raise Exception("ERROR: Unknown snapshot version!")

		#FIXME hard-coded page size!
		self.s_map_lookup = {}
		for map in self.s_maps:
			for i in range(map[0],map[0] + map[1], 4096):
				self.s_map_lookup[i] = map

		self.attached = True
		# So that we pickle
		self.bplock = None
		self.thread = None

	def saveToFile(self, filename):
		"""
		Save a snapshot to file for later reading in...
		"""
		#import zlib
		f = file(filename, "wb")
		pickle.dump(self.s_snapdict, f)
		#f.write(zlib.compress(rawbytes))
		f.close()

	def getMap(self, addr):
		base = addr & 0xfffff000
		return self.s_map_lookup.get(base, None)

	def platformGetFds(self):
		return self.s_fds

	def getExe(self):
		return self.s_exe

	def getStackTrace(self):
		tid = self.getMeta("ThreadId")
		tr = self.s_stacktrace.get(tid, None)
		if tr == None:
			raise Exception("ERROR: Invalid thread id specified")
		return tr

	def archGetSpName(self):
		return self.s_spname

	def archGetPcName(self):
		return self.s_pcname

	def platformGetMaps(self):
		return self.s_maps

	def getRegisterFormat(self):
		# Fake this out for the Trace constructor
		return ""

	def getRegisterNames(self):
		return []

	def platformGetThreads(self):
		return self.s_threads


	def platformReadMemory(self, address, size):
		map = self.getMap(address)
		if map == None:
			raise Exception("ERROR: platformReadMemory says no map for 0x%.8x" % address)
		offset = address - map[0] # Base address
		mapbytes = self.s_mem.get(map[0], None)
		if mapbytes == None:
			raise PlatformException("ERROR: Memory map at 0x%.8x is not backed!" % map[0])
		if len(mapbytes) == 0:
			raise PlatformException("ERROR: Memory Map at 0x%.8x is backed by ''" % map[0])

		ret = mapbytes[offset:offset+size]
		rlen = len(ret)
		# We may have a cross-map read, just recurse for the rest
		if rlen != size:
			ret += self.platformReadMemory(address+rlen, size-rlen)
		return ret

	def platformWriteMemory(self, address, bytes):
		map = self.getMap(address)
		if map == None:
			raise Exception("ERROR: platformWriteMemory says no map for 0x%.8x" % address)
		offset = address - map[0]
		mapbytes = self.s_mem[map[0]]
		self.s_mem[map[0]] = mapbytes[:offset] + bytes + mapbytes[offset+len(bytes):]

	def platformDetach(self):
		pass

	# Over-ride register *caching* subsystem to store/retrieve
	# register information in pure dictionaries
	def cacheRegs(self):
		if self.regcache == None:
			tid = self.getMeta("ThreadId")
			self.regcache = self.s_regs.get(tid)

	def syncRegs(self):
		if self.regcachedirty:
			tid = self.getMeta("ThreadId")
			self.s_regs[tid] = self.regcache
			self.regcachedirty = False
		self.regcache = None

class TraceGroup(Notifier, v_util.TraceManager):
	"""
	Encapsulate several traces, run them, and continue to 
	handle their event notifications.
	"""
	def __init__(self):
		Notifier.__init__(self)
		v_util.TraceManager.__init__(self)
		self.traces = {}
		self.go = True # A little ghetto switch for those who read the source

		# We are a notify all notifier by default
		self.registerNotifier(NOTIFY_ALL, self)

		self.setMode("NonBlocking", True)

	def setMeta(self, name, value):
		"""
		A trace group's setMeta function will set "persistant" metadata
		which will be added again to any trace on attach.  Additionally,
		setting metadata on a tracegroup will cause all current traces
		to get the update as well....
		"""
		v_util.TraceManager.setMeta(self,name,value)
		for trace in self.traces.values():
			trace.setMeta(name, value)

	def setMode(self, name, value):
		v_util.TraceManager.setMode(self, name, value)
		for trace in self.getTraces():
			trace.setMode(name, value)

	def detachAll(self):
		"""
		Detach from ALL the currently targetd processes
		"""
		for trace in self.traces.values():
			try:
				if trace.isRunning():
					trace.sendBreak()
				trace.detach()
			except:
				pass

	def run(self):
		"""
		Our run method  is a little different than a traditional
		trace. It will *never* block.
		"""
		if len(self.traces.keys()) == 0:
			raise Exception("ERROR - can't run() with no traces!")

		for trace in self.traces.values():

			if trace.exited:
				self.traces.pop(trace.pid)
				trace.detach()
				continue

			if not trace.isRunning():
				trace.run()

	def execTrace(self, cmdline):
		trace = getTrace()
		self.initTrace(trace)
		trace.execute(cmdline)
		self.traces[trace.getPid()] = trace
		return trace

	def addTrace(self, proc):
		"""
		Add a new tracer to this group the "proc" argument
		may be either an long() for a pid (which we will attach
		to) or an already attached (and broken) tracer object.
		"""

		if (type(proc) == types.IntType or
			type(proc) == types.LongType):
			trace = getTrace()
			self.initTrace(trace)
			self.traces[proc] = trace
			try:
				trace.attach(proc)
			except:
				self.delTrace(proc)
				raise

		else: # Hopefully a tracer object... if not.. you're dumb.
			trace = proc
			self.initTrace(trace)
			self.traces[trace.getPid()] = trace

		return trace

	def initTrace(self, trace):
		"""
		 - INTERNAL -
		Setup a tracer object to be ready for being in this
		trace group (setup modes and notifiers).  Only addTrace()
		and execTrace() probably need to be aware of this.
		"""
		self.manageTrace(trace)

	def delTrace(self, pid):
		"""
		Remove a trace from the current TraceGroup
		"""
		trace = self.traces.pop(pid, None)
		self.unManageTrace(trace)

	def getTraces(self):
		"""
		Return a list of the current traces
		"""
		return self.traces.values()

	def getTraceByPid(self, pid):
		"""
		Return the the trace for process PID if we're
		already attached.  Return None if not.
		"""
		return self.traces.get(pid, None)

	def notify(self, event, trace):
		# Remove this trace, and free it
		# on the server if present
		if event == NOTIFY_EXIT:
			self.delTrace(trace.getPid())

class VtraceExpression:
	"""
	A vtrace expression is essentially python code with a bunch of metadata
	mapped into the code evaluation namespace.  Currently, every method listed
	in this class except "evaluate" also gets mapped into the space.  This means
	that the expressions may call methods from this object as though they were
	functions ie. the expression:

	mapbase(<address>)

	will call the mapbase method from this object...

	Additionally the following items are mapped directly into the namespace for
	evaluation:

	* Registers
		Mapped in by name

	* Symbol Resolvers 
		They are accessable by the "normalized libname" so, kernel32.dll is "kernel32"
		and /usr/lib/libpthread-2.0.40.so is "libpthread".  These resolvers may be
		dereferenced to get symbols by name.  For example the expression "kernel32.CloseHandle"
		will return the address of the CloseHandle symbol from kernel32

	"""
	def __init__(self, expression):
		self.trace = None
		self.expression = expression

	def __str__(self):
		return self.expression

	def evaluate(self, trace, noraise=False):
		"""
		Evaluate the expression with metadata/symbols/registers/etc
		from the given tracer.  This *will* raise exceptions on 
		parse errors or invalid symbols etc unless you specify
		noraise at which point it will return None.
		"""
		methmap = {
			"frame":self.frame,
			"section":self.section,
			"sectionlen":self.sectionlen,
			"teb":self.teb,
			"poi":self.poi,
			"maplen":self.maplen,
			"mapbase":self.mapbase,
			"struct":self.struct
			}

		try:
			locs = {}
			self.trace = trace
			locs.update(trace.getRegisters())
			locs.update(methmap)
			locs.update(trace.resbynorm)
			locs["trace"] = trace
			if trace.getMeta("Platform", "Windows"):
				locs["peb"] = trace.getMeta("PEB")
			x = long(eval(self.expression,{},locs))
			self.trace = None
			return x
		except Exception, e:
			self.trace = None
			if noraise:
				if vtrace.verbose: print e
				return None
			raise

	def struct(self, sname, saddr):
		"""
		Return a VStruct structure of type "sname" which has been
		populated with the values from saddr.

		Usage: struct("PEB", <peb address>)
		"""
		return self.trace.getStruct(sname, saddr)

	def frame(self, index):
		"""
		Return the address of the saved base pointer for
		the specified frame.

		Usage: frame(<index>)
		"""
		stack = self.trace.getStackTrace()
		return stack[index][1]

	def section(self, secname, filename=None):
		"""
		Return the address of the section specified, if 
		filename is specified, use only that file to resolve
		the section name.

		Usage: section(<secname> [, <filename>])
		"""
		if not filename:
			filename = self.trace.getExe()
		sym = self.trace.getSymByName(secname, filename)
		return long(sym)

	def sectionlen(self, secname, filename=None):
		"""
		Return the length of the requested section. If not present
		the "libname" defaults to the primary executable.  If
		*present*, the libname must be a "normalized" library
		name (kernel32.dll == kernel32, /usr/lib/libfoo.1.30-3.so == libfoo).

		Usage: sectionlen(<secname> [,<libname>])
		"""
		if not filename:
			filename = self.trace.getExe()

		sym = self.trace.getSymByName(secname, filename)
		return long(sym)

	def teb(self, threadnum=-1):
		"""
		The expression teb(threadid) will return whatever the
		platform stores as the int for threadid.  In the case
		of windows, this is the TEB, others may be the thread
		stack base or whatever.  If threadid is left out, it
		uses the threadid of the current thread context.
		"""
		if threadnum < 0:
			# Get the thread ID of the current Thread Context
			threadnum = self.trace.getMeta("ThreadId")

		teb = self.trace.getThreads().get(threadnum, None)
		if teb == None:
			raise Exception("ERROR - Unknown Thread Id %d" % threadnum)

		return teb

	def poi(self, address):
		"""
		When expressions contain "poi(ebp)" this will return
		the address pointed to by ebp.
		"""
		return self.trace.readMemoryFormat(address, "P")[0]

	def maplen(self, address):
		"""
		The expression maplen(address) returns the length of the
		memory mapped area containing "address".
		"""
		map = self.trace.getMap(address)
		if not map:
			raise Exception("ERROR - un-mapped address in maplen()")
		return map[1]

	def mapbase(self, address):
		"""
		The expression mapbase(address) returns the base address of the
		memory mapped area containing "address"
		"""
		map = self.trace.getMap(address)
		if not map:
			raise Exception("ERROR - un-mapped address in mapbase()")
		return map[0]

############################################################
# Platform mixins get thrown together here to form voltron
############################################################

def getTrace():
	"""
	Return a tracer object appropriate for this platform.
	This is the function you will use to get a tracer object
	with the appropriate ancestry for your host.
	ex. mytrace = vtrace.getTrace()
	"""

	if remote: #We have a remote server!
		return getRemoteTrace()


	os_name = platform.system() # Like "Linux", "Darwin","Windows"
	arch = platform.machine()   # 'i386','ppc', etc...
	# This bits calculation is not safe for 128 bit systems
	bits = int(platform.architecture()[0][:2])

	ilist = [object,] # Inheritors list
	ilist.append(Trace)
	ilist.append(v_base.BasePlatformMixin)
	ilist.append(v_base.UtilMixin)

	if os_name == "Linux":
		import vtrace.platforms.posix as v_posix
		import vtrace.platforms.linux as v_linux
		ilist.append(v_posix.PosixMixin)
		ilist.append(v_posix.ElfMixin)
		if arch == "x86_64":
			#Order matters.
			import vtrace.archs.amd64 as v_amd64
			ilist.append(v_amd64.Amd64Mixin)
			ilist.append(v_posix.PtraceMixin)
			ilist.append(v_linux.LinuxMixin)
			ilist.append(v_linux.LinuxAmd64Registers)

		elif arch in ("i386","i486","i586","i686"):
			import vtrace.archs.intel as v_intel
			ilist.append(v_intel.IntelMixin)
			ilist.append(v_posix.PtraceMixin)
			ilist.append(v_linux.LinuxMixin)
			ilist.append(v_linux.LinuxIntelRegisters)

		else:
			raise Exception("Sorry, no linux support for %s" % arch)

	elif os_name == "FreeBSD":
		import vtrace.platforms.posix as v_posix
		import vtrace.platforms.freebsd as v_freebsd
		ilist.append(v_posix.PosixMixin)
		ilist.append(v_posix.ElfMixin)
		if arch in ("i386","i486","i586","i686"):
			import vtrace.archs.intel as v_intel
			ilist.append(v_intel.IntelMixin)
			ilist.append(v_freebsd.FreeBSDMixin)
			ilist.append(v_freebsd.FreeBSDIntelRegisters)
		else:
			raise Exception("Sorry, no FreeBSD support for %s" % arch)

	elif os_name == "sunos5":
		print "SOLARIS SUPPORT ISNT DONE"
		import vtrace.platforms.posix as v_posix
		import vtrace.platforms.solaris as v_solaris
		ilist.append(v_posix.PosixMixin)
		if arch == "i86pc":
			import vtrace.archs.intel as v_intel
			ilist.append(v_intel.IntelMixin)
			ilist.append(v_solaris.SolarisMixin)
			ilist.append(v_solaris.SolarisIntelMixin)

	elif os_name == "Darwin":
		#print "DARWIN SUPPORT ISNT DONE"
		#if 9 not in os.getgroups():
		#	raise Exception("You must be in the procmod group!")
		import vtrace.platforms.darwin as v_darwin
		import vtrace.platforms.posix as v_posix
		ilist.append(v_posix.PosixMixin)
		ilist.append(v_posix.PtraceMixin)
		ilist.append(v_darwin.DarwinMixin)
		ilist.append(v_darwin.MachoMixin)
		if arch == "i386" or arch == "x86_64":
			import vtrace.archs.intel as v_intel
			ilist.append(v_intel.IntelMixin)
			ilist.append(v_darwin.DarwinIntel32Registers)
		elif arch == "powerpc":
			import vtrace.archs.ppc as v_ppc
			ilist.append(v_ppc.PpcMixin)
			ilist.append(v_darwin.DarwinPpc32Registers)
		else:
			raise Exception("WTF?!?!  You got Darwin running on %s?!?>!?" % arch)

	elif os_name == "Windows":
		import vtrace.platforms.win32 as v_win32
		import vtrace.archs.intel as v_intel
		ilist.append(v_win32.PEMixin)
		ilist.append(v_intel.IntelMixin)
		ilist.append(v_win32.Win32Mixin)

	else:
		raise Exception("ERROR - OS %s not supported yet" % os_name)

	ilist.reverse()
	ttype = type("Trace", tuple(ilist), {})
	trace = ttype()

	# Lets let *any* mixin define a initMixin() routine
	# (mostly for initing modes)
	for cls in inspect.getmro(trace.__class__):
		# Skip the first class so it doesn't
		# fall through to the first inherited one
		if cls.__name__ == "Trace":
			continue
		if hasattr(cls, "initMixin"):
			cls.initMixin(trace)

	return trace

def interact(pid=0,server=None,trace=None):

	"""
	Just a cute and dirty way to get a tracer attached to a pid
	and get a python interpreter instance out of it.
	"""

	global remote
	remote = server

	if trace == None:
		trace = getTrace()
		if pid:
			trace.attach(pid)

	mylocals = {}
	mylocals["trace"] = trace

	code.interact(local=mylocals)

