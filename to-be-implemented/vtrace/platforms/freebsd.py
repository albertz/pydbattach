"""
FreeBSD support...
"""

import os
import ctypes
import ctypes.util as cutil

import vtrace
import vtrace.platforms.posix as v_posix
import vtrace.util as v_util

libkvm = ctypes.CDLL(cutil.find_library("kvm"))

# kvm_getprocs cmds
KERN_PROC_ALL           = 0       # everything
KERN_PROC_PID           = 1       # by process id
KERN_PROC_PGRP          = 2       # by process group id
KERN_PROC_SESSION       = 3       # by session of pid
KERN_PROC_TTY           = 4       # by controlling tty
KERN_PROC_UID           = 5       # by effective uid
KERN_PROC_RUID          = 6       # by real uid
KERN_PROC_ARGS          = 7       # get/set arguments/proctitle
KERN_PROC_PROC          = 8       # only return procs
KERN_PROC_SV_NAME       = 9       # get syscall vector name
KERN_PROC_RGID          = 10      # by real group id
KERN_PROC_GID           = 11      # by effective group id
KERN_PROC_PATHNAME      = 12      # path to executable
KERN_PROC_INC_THREAD    = 0x10    # Include threads in filtered results

pid_t = ctypes.c_int32
lwpid_t = ctypes.c_int32
void_p = ctypes.c_void_p
dev_t = ctypes.c_uint32
sigset_t = ctypes.c_uint32*4
uid_t = ctypes.c_uint32
gid_t = ctypes.c_uint32
fixpt_t = ctypes.c_uint32

vm_size_t = ctypes.c_uint32 # FIXME this should maybe be 64 bit safe
segsz_t = ctypes.c_uint32 # FIXME this should maybe be 64 bit safe

# Could go crazy and grep headers for this stuff ;)
KI_NGROUPS = 16
OCOMMLEN = 16
WMESGLEN = 8
LOGNAMELEN = 17
LOCKNAMELEN = 8
COMMLEN = 19
KI_EMULNAMELEN = 16
KI_NSPARE_INT = 10
KI_NSPARE_PTR = 7
KI_NSPARE_LONG = 12


def c_buf(size):
    return ctypes.c_char * size

class PRIORITY(ctypes.Structure):
    _fields_ = (
        ("pri_class", ctypes.c_ubyte),
        ("pri_level", ctypes.c_ubyte),
        ("pri_native", ctypes.c_ubyte),
        ("pri_user", ctypes.c_ubyte)
    )

class TIMEVAL(ctypes.Structure):
    _fields_ = (
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_long)
    )

class RUSAGE(ctypes.Structure):
    _fields_ = (
        ("ru_utime", TIMEVAL),          # user time used
        ("ru_stime", TIMEVAL),          # system time used
        ("ru_maxrss", ctypes.c_long),   #
        ("ru_ixrss", ctypes.c_long),    # (j) integral shared memory size
        ("ru_idrss", ctypes.c_long),    # (j) integral unshared data
        ("ru_isrss", ctypes.c_long),    # (j) integral unshared stack
        ("ru_minflt", ctypes.c_long),   # (c) page reclaims
        ("ru_majflt", ctypes.c_long),   # (c) page faults
        ("ru_nswap", ctypes.c_long),    # (c + j) swaps
        ("ru_inblock", ctypes.c_long),  # (n) block input operations
        ("ru_oublock", ctypes.c_long),  # (n) block output operations
        ("ru_msgsnd", ctypes.c_long),   # (n) messages sent
        ("ru_msgrcv", ctypes.c_long),   # (n) messages received
        ("ru_nsignals", ctypes.c_long), # (c) signals received
        ("ru_nvcsw", ctypes.c_long),    # (j) voluntary context switches
        ("ru_nivcsw", ctypes.c_long),   # (j) involuntary
    )


class KINFO_PROC(ctypes.Structure):
    _fields_ = (
        ("ki_structsize", ctypes.c_int),# size of this structure
        ("ki_layout", ctypes.c_int),    # reserved: layout identifier
        ("ki_args", void_p),            # address of command arguments (struct pargs*)
        ("ki_paddr", void_p),           # address of proc (struct proc*)
        ("ki_addr", void_p),            # kernel virtual addr of u-area (struct user*)
        ("ki_tracep", void_p),          # pointer to trace file (struct vnode *)
        ("ki_textvp", void_p),          # pointer to executable file (struct vnode *)
	("ki_fd", void_p),              # pointer to open file info (struct filedesc  *)
        ("ki_vmspace", void_p),         # pointer to kernel vmspace struct (struct vmspace *)
        ("ki_wchan", void_p),           # sleep address (void*)
	("ki_pid", pid_t),              # Process identifier
        ("ki_ppid", pid_t),             # parent process id
        ("ki_pgid", pid_t),             # process group id
        ("ki_tpgid", pid_t),            # tty process group id
        ("ki_sid", pid_t),              # Process session ID
        ("ki_tsid", pid_t),             # Terminal session ID
        ("ki_jobc", ctypes.c_short),    # job control counter
        ("ki_spare_short1", ctypes.c_short), #
        ("ki_tdev", dev_t),             # controlling tty dev
        ("ki_siglist", sigset_t),       # Signals arrived but not delivered
        ("ki_sigmask", sigset_t),       # Current signal mask
        ("ki_sigignore", sigset_t),     # Signals being ignored
        ("ki_sigcatch", sigset_t),      # Signals being caught by user
        ("ki_uid", uid_t),              # effective user id
        ("ki_ruid", uid_t),             # Real user id
        ("ki_svuid", uid_t),            # Saved effective user id
        ("ki_rgid", gid_t),             # Real group id
        ("ki_svgid", gid_t),            # Saved effective group id
        ("ki_ngroups", ctypes.c_short), # number of groups
        ("ki_spare_short2", ctypes.c_short),
        ("ki_groups", gid_t * KI_NGROUPS), # groups
        ("ki_size", vm_size_t),         # virtual size
        ("ki_rssize", segsz_t),         # current resident set size in pages
        ("ki_swrss", segsz_t),          # resident set size before last swap
        ("ki_tsize", segsz_t),          # text size (pages) XXX
        ("ki_dsize", segsz_t),          # data size (pages) XXX
        ("ki_ssize", segsz_t),          # stack size (pages)
        ("ki_xstat", ctypes.c_ushort),  # Exit status for wait and stop signal
        ("ki_acflag", ctypes.c_ushort), # Accounting flags
        ("ki_pctcpu", fixpt_t),         # %cpu for process during ki_swtime
        ("ki_estcpu", ctypes.c_uint),   # Time averaged value of ki_cpticks
        ("ki_slptime", ctypes.c_uint),  # Time since last blocked
        ("ki_swtime", ctypes.c_uint),   # Time swapped in or out
        ("ki_spareint1", ctypes.c_int), # unused (just here for alignment)
        ("ki_runtime", ctypes.c_uint64),# Real time in microsec
        ("ki_start", TIMEVAL),          # starting time
        ("ki_childtime", TIMEVAL),      # time used by process children
        ("ki_flag", ctypes.c_long),     # P_* flags
        ("ki_kiflag", ctypes.c_long),   # KI_* flags
        ("ki_traceflag", ctypes.c_int), # kernel trace points
        ("ki_stat", ctypes.c_char),     # S* process status
        ("ki_nice", ctypes.c_ubyte),    # Process "nice" value
        ("ki_lock", ctypes.c_char),     # Process lock (prevent swap) count
        ("ki_rqindex", ctypes.c_char),  # Run queue index
        ("ki_oncpu", ctypes.c_char),    # Which cpu we are on
        ("ki_lastcpu", ctypes.c_char),  # Last cpu we were on
        ("ki_ocomm", c_buf(OCOMMLEN+1)),      # command name
        ("ki_wmesg", c_buf(WMESGLEN+1)),      # wchan message
        ("ki_login", c_buf(LOGNAMELEN+1)),    # setlogin name
        ("ki_lockname", c_buf(LOCKNAMELEN+1)),# lock name
        ("ki_comm", c_buf(COMMLEN+1)),        # command name
        ("ki_emul", c_buf(KI_EMULNAMELEN+1)), # emulation name
        ("ki_sparestrings",c_buf(68)),   # spare string space
        ("ki_spareints", ctypes.c_int*KI_NSPARE_INT),
        ("ki_jid", ctypes.c_int),       # Process jail ID
        ("ki_numthreads", ctypes.c_int),# KSE number of total threads
        ("ki_tid", lwpid_t),            # thread id
        ("ki_pri", PRIORITY),           # process priority
        ("ki_rusage", RUSAGE),          # process rusage statistics
        # XXX - most fields in ki_rusage_ch are not (yet) filled in
        ("ki_rusage_ch", RUSAGE),       # rusage of children processes
        ("ki_pcb", void_p),             # kernel virtual addr of pcb
        ("ki_kstack", void_p),          # kernel virtual addr of stack
        ("ki_udata", void_p),           # User convenience pointer
        ("ki_spareptrs", void_p*KI_NSPARE_PTR),
        ("ki_sparelongs", ctypes.c_long*KI_NSPARE_LONG),
        ("ki_sflag", ctypes.c_long),    # PS_* flags
        ("ki_tdflags", ctypes.c_long),  # KSE kthread flag
    )

# All the FreeBSD ptrace defines
PT_TRACE_ME     = 0       #/* child declares it's being traced */
PT_READ_I       = 1       #/* read word in child's I space */
PT_READ_D       = 2       #/* read word in child's D space */
PT_WRITE_I      = 4       #/* write word in child's I space */
PT_WRITE_D      = 5       #/* write word in child's D space */
PT_CONTINUE     = 7       #/* continue the child */
PT_KILL         = 8       #/* kill the child process */
PT_STEP         = 9       #/* single step the child */
PT_ATTACH       = 10      #/* trace some running process */
PT_DETACH       = 11      #/* stop tracing a process */
PT_IO           = 12      #/* do I/O to/from stopped process. */
PT_LWPINFO      = 13      #/* Info about the LWP that stopped. */
PT_GETNUMLWPS   = 14      #/* get total number of threads */
PT_GETLWPLIST   = 15      #/* get thread list */
PT_CLEARSTEP    = 16      #/* turn off single step */
PT_SETSTEP      = 17      #/* turn on single step */
PT_SUSPEND      = 18      #/* suspend a thread */
PT_RESUME       = 19      #/* resume a thread */
PT_TO_SCE       = 20      # Stop on syscall entry
PT_TO_SCX       = 21      # Stop on syscall exit
PT_SYSCALL      = 22      # Stop on syscall entry and exit
PT_GETREGS      = 33      #/* get general-purpose registers */
PT_SETREGS      = 34      #/* set general-purpose registers */
PT_GETFPREGS    = 35      #/* get floating-point registers */
PT_SETFPREGS    = 36      #/* set floating-point registers */
PT_GETDBREGS    = 37      #/* get debugging registers */
PT_SETDBREGS    = 38      #/* set debugging registers */
#PT_FIRSTMACH    = 64      #/* for machine-specific requests */

# On PT_IO addr is a pointer to a struct

class PTRACE_IO_DESC(ctypes.Structure):
    _fields_ = [
        ("piod_op", ctypes.c_int),      # I/O operation
        ("piod_offs", ctypes.c_void_p), # Child offset
        ("piod_addr", ctypes.c_void_p), # Parent Offset
        ("piod_len", ctypes.c_uint)     # Size
    ]

# Operations in piod_op.
PIOD_READ_D     = 1       # Read from D space
PIOD_WRITE_D    = 2       # Write to D space
PIOD_READ_I     = 3       # Read from I space
PIOD_WRITE_I    = 4       # Write to I space

class PTRACE_LWPINFO(ctypes.Structure):
    _fields_ = (
        ("pl_lwpid", lwpid_t),
        ("pl_event", ctypes.c_int),
        ("pl_flags", ctypes.c_int),
        ("pl_sigmask", sigset_t),
        ("pl_siglist", sigset_t),
    )

PL_EVENT_NONE   = 0
PL_EVENT_SIGNAL = 1

PL_FLAGS_SA    = 0
PL_FLAGS_BOUND = 1

class FreeBSDMixin:

    def initMixin(self):
        self.initMode("Syscall", False, "Break on Syscalls")
        self.kvmh = libkvm.kvm_open(None, None, None, 0, "vtrace")

    def finiMixin(self):
        print "FIXME I DON'T THINK THIS IS BEING CALLED"
        if self.kvmh != None:
            libkvm.kvm_close(self.kvmh)

    def platformReadMemory(self, address, size):
        #FIXME optimize for speed!
        iod = PTRACE_IO_DESC()
        buf = ctypes.create_string_buffer(size)

        iod.piod_op = PIOD_READ_D
        iod.piod_addr = ctypes.addressof(buf)
        iod.piod_offs = address
        iod.piod_len = size

        if v_posix.ptrace(PT_IO, self.pid, ctypes.addressof(iod), 0) != 0:
            raise Exception("ptrace PT_IO failed to read 0x%.8x" % address)

        return buf.raw

    def platformWriteMemory(self, address, buf):
        #FIXME optimize for speed!
        iod = PTRACE_IO_DESC()

        cbuf = ctypes.create_string_buffer(buf)

        iod.piod_op = PIOD_WRITE_D
        iod.piod_addr = ctypes.addressof(cbuf)
        iod.piod_offs = address
        iod.piod_len = len(buf)

        if v_posix.ptrace(PT_IO, self.pid, ctypes.addressof(iod), 0) != 0:
            raise Exception("ptrace PT_IO failed to read 0x%.8x" % address)

    def platformAttach(self, pid):
        if v_posix.ptrace(PT_ATTACH, pid, 0, 0) != 0:
            raise Exception("Ptrace Attach Failed")

    def platformExec(self, cmdline):
        # Basically just like the one in the Ptrace mixin...
        self.execing = True
        cmdlist = v_util.splitargs(cmdline)
        os.stat(cmdlist[0])
        pid = os.fork()
        if pid == 0:
            v_posix.ptrace(PT_TRACE_ME, 0, 0, 0)
            os.execv(cmdlist[0], cmdlist)
            sys.exit(-1)
        return pid

    def platformWait(self):
        status = v_posix.PosixMixin.platformWait(self)
        # Get the thread id from the ptrace interface

        info = PTRACE_LWPINFO()
        size = ctypes.sizeof(info)
        if v_posix.ptrace(PT_LWPINFO, self.pid, ctypes.byref(info), size) == 0:
            self.setMeta("ThreadId", info.pl_lwpid)
        else:
            #FIXME this is because posix wait is linux specific and broke
            self.setMeta("ThreadId", self.pid)

        return status

    def platformStepi(self):
        self.stepping = True
        if v_posix.ptrace(PT_STEP, self.pid, 1, 0) != 0:
            raise Exception("ptrace PT_STEP failed!")

    def platformContinue(self):
        cmd = PT_CONTINUE
        if self.getMode("Syscall"):
            cmd = PT_SYSCALL

        sig = self.getMeta("PendingSignal", 0)
        # In freebsd address is the place to continue from
        # but 1 means use existing EIP
        if v_posix.ptrace(cmd, self.pid, 1, sig) != 0:
            raise Exception("ptrace PT_CONTINUE/PT_SYSCALL failed")

    #def platformExec(self, cmdline):

    def platformDetach(self):
        if v_posix.ptrace(PT_DETACH, self.pid, 1, 0) != 0:
            raise Exception("Ptrace Detach Failed")

    def platformGetThreads(self):
        ret = {}
        cnt = self._getThreadCount()
        buf = (ctypes.c_int * cnt)()
        if v_posix.ptrace(PT_GETLWPLIST, self.pid, buf, cnt) != cnt:
            raise Exception("ptrace PW_GETLWPLIST failed")
        for x in buf:
            ret[x] = x
        return ret

    def _getThreadCount(self):
        return v_posix.ptrace(PT_GETNUMLWPS, self.pid, 0, 0)

    def platformGetFds(self):
        return []

    def platformGetMaps(self):
        # FIXME make this not need proc
        ret = []
        mpath = "/proc/%d/map" % self.pid
        if not os.path.isfile(mpath):
            raise Exception("Memory map enumeration requires /proc on FreeBSD")

        mapfile = file(mpath, "rb")
        for line in mapfile:
            perms = 0
            fname = ""
            maptup = line.split(None, 12)
            base = int(maptup[0], 16)
            max  = int(maptup[1], 16)
            permstr = maptup[5]

            if maptup[11] == "vnode":
                fname = maptup[12].strip()

            if permstr[0] == 'r':
                perms |= vtrace.MM_READ

            if permstr[1] == 'w':
                perms |= vtrace.MM_WRITE

            if permstr[2] == 'x':
                perms |= vtrace.MM_EXEC

            ret.append((base, max-base, perms, fname))

        return ret

    def platformPs(self):
        ret = []
        cnt = ctypes.c_uint(0)
        kinfo = KINFO_PROC()
        ksize = ctypes.sizeof(kinfo)
        kaddr = ctypes.addressof(kinfo)

        p = libkvm.kvm_getprocs(self.kvmh, KERN_PROC_PROC, 0, ctypes.addressof(cnt))
        for i in xrange(cnt.value):
            ctypes.memmove(kaddr, p + (i*ksize), ksize)
            if kinfo.ki_structsize != ksize:
                print "WARNING: KINFO_PROC CHANGED SIZE, Trying to account for it... good luck"
                ksize = kinfo.ki_structsize
            ret.append((kinfo.ki_pid, kinfo.ki_comm))

        return ret

GEN_REG_CNT = 19
DBG_REG_CNT = 8
TOT_REG_CNT = GEN_REG_CNT + DBG_REG_CNT

class FreeBSDIntelRegisters:

    def platformGetRegs(self):
        buf = ctypes.create_string_buffer(TOT_REG_CNT*4)
        #FIXME thread specific
        if v_posix.ptrace(PT_GETREGS, self.pid, buf, 0) != 0:
            raise Exception("ptrace PT_GETREGS failed!")
        if v_posix.ptrace(PT_GETDBREGS, self.pid, ctypes.addressof(buf)+(GEN_REG_CNT*4), 0) != 0:
            raise Exception("ptrace PT_GETDBREGS failed!")
        return buf.raw

    def platformSetRegs(self, buf):
        #FIXME thread specific
        if v_posix.ptrace(PT_SETREGS, self.pid, buf, 0) != 0:
            raise Exception("ptrace PT_SETREGS failed!")
        if v_posix.ptrace(PT_SETDBREGS, self.pid, buf[(GEN_REG_CNT*4):], 0) != 0:
            raise Exception("ptrace PT_SETDBREGS failed!")

    def getRegisterFormat(self):
        return "<27L"

    def getRegisterNames(self):
        return ["fs","es","ds","edi","esi","ebp","isp",
                "ebx","edx","ecx","eax","trapno","err",
                "eip","cs","eflags","esp","ss","gs","debug0",
                "debug1","debug2","debug3","debug4","debug5",
                "debug6","debug7"]
                

