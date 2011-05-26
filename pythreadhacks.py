import ctypes
import _ctypes

pyapi = ctypes.pythonapi
PyObj_FromPtr = _ctypes.PyObj_FromPtr

import thread, time, sys


def find_thread(frame):
	for t,f in sys._current_frames().items():
		while f is not None:
			if f == frame: return t
			f = f.f_back
	return None


mainthread = thread.get_ident()

def tracefunc(frame,ev,arg):
	thread = find_thread(frame)
	if thread == mainthread: pass
	else:
		#print "trace", ev, "from thread", thread
		pass
	return tracefunc

def dummytracer(*args): return dummytracer


import pythonhdr
from pythonhdr import PyObject, Py_ssize_t
CO_MAXBLOCKS = 20 # from Python/Include/code.h
POINTER = ctypes.POINTER
PPyObject = POINTER(PyObject)
c_int, c_long = ctypes.c_int, ctypes.c_long

def Py_INCREF(pyobj): pyobj.contents.ob_refcnt += 1
def Py_DECREF(pyobj): pyobj.contents.ob_refcnt -= 1
def Py_XINCREF(pyobj):
	if pyobj: Py_INCREF(pyobj)
def Py_XDECREF(pyobj):
	if pyobj: Py_DECREF(pyobj)

# see frameobject.h for PyTryBlock and PyFrameObject

class PyTryBlock(ctypes.Structure):
	_fields_ = [
		("b_type", c_int),
		("b_handler", c_int),
		("b_level", c_int),
	]

class PyThreadState(ctypes.Structure): pass # predeclaration, see below

class PyFrameObject(PyObject):
	_fields_ = [
		("ob_size", Py_ssize_t), # from PyObject_VAR_HEAD
		# start of PyFrameObject
		("f_back", PPyObject),
		("f_code", PPyObject),
		("f_builtins", PPyObject),
		("f_globals", PPyObject),
		("f_locals", PPyObject),
		("f_valuestack", POINTER(PPyObject)),
		("f_stacktop", POINTER(PPyObject)),
		("f_trace", PPyObject),
		("f_exc_type", PPyObject),
		("f_exc_value", PPyObject),
		("f_exc_traceback", PPyObject),
		("f_tstate", POINTER(PyThreadState)),
		("f_lasti", c_int),
		("f_lineno", c_int),
		("f_iblock", c_int),
		("f_blockstack", PyTryBlock * 20),
		("f_localsplus", PPyObject),
	]

# see pystate.h for PyThreadState

# typedef int (*Py_tracefunc)(PyObject *, struct _frame *, int, PyObject *);
Py_tracefunc = ctypes.CFUNCTYPE(c_int, PPyObject, POINTER(PyFrameObject), c_int, PPyObject)

class PyInterpreterState(ctypes.Structure): pass # not yet needed

PyThreadState._fields_ = [
		("next", POINTER(PyThreadState)),
		("interp", POINTER(PyInterpreterState)),
		("frame", POINTER(PyFrameObject)),
		("recursion_depth", c_int),
		("tracing", c_int),
		("use_tracing", c_int),
		("c_profilefunc", Py_tracefunc),
		("c_tracefunc", Py_tracefunc),
		("c_profileobj", PPyObject),
		("c_traceobj", PPyObject),
		("curexc_type", PPyObject),
		("curexc_value", PPyObject),
		("curexc_traceback", PPyObject),
		("exc_type", PPyObject),
		("exc_value", PPyObject),
		("exc_traceback", PPyObject),
		("dict", PPyObject),
		("tick_counter", c_int),
		("gilstate_counter", c_int),
		("async_exc", PPyObject),
		("thread_id", c_long),
	]


def getPPyObjectPtr(pyobj):
	if not pyobj: return 0
	return _ctypes.addressof(pyobj.contents)

def PPyObject_FromObj(obj):
	return PPyObject(PyObject.from_address(id(obj)))
	
def getThreadState(frame):
	frame = PyFrameObject.from_address(id(frame))
	tstate = frame.f_tstate.contents
	return tstate

def getTickCounter(frame):
	return getThreadState(frame).tick_counter


c_tracefunc_trampoline = None
def initCTraceFuncTrampoline():
	global c_tracefunc_trampoline
	
	origtrace = sys.gettrace() # remember orig
	sys.settrace(dummytracer) # it doesn't really matter which tracer, we always get the same trampoline
	
	frame = sys._getframe()
	tstate = getThreadState(frame)
	
	c_tracefunc_trampoline = tstate.c_tracefunc
	
	sys.settrace(origtrace) # recover
initCTraceFuncTrampoline()	

	
def _setTraceOfThread(tstate, func, arg):
	assert type(tstate) is PyThreadState
	assert type(func) is Py_tracefunc
	assert type(arg) is PPyObject
	
	tstate.use_tracing = 0 # disable while we are in here. just for safety
	
	# we assume _Py_TracingPossible > 0 here. we cannot really change it anyway
	# this is basically copied from PyEval_SetTrace in ceval.c
	temp = tstate.c_traceobj # PPyObject
	Py_XINCREF(arg)
	tstate.c_tracefunc = Py_tracefunc()
	tstate.c_traceobj = PPyObject()
	# Must make sure that profiling is not ignored if 'temp' is freed
	tstate.use_tracing = int(bool(tstate.c_profilefunc))
	Py_XDECREF(temp)
	tstate.c_tracefunc = func
	tstate.c_traceobj = arg
	# Flag that tracing or profiling is turned on
	tstate.use_tracing = int(bool(func) or bool(tstate.c_profilefunc))

def _setTraceFuncOnFrames(frame, tracefunc):
	while frame is not None:
		frame.f_trace = tracefunc
		frame = frame.f_back

# NOTE: This only works if at least one tracefunc is currently installed via sys.settrace().
# This is because we need _Py_TracingPossible > 0.
def setTraceOfThread(tid, tracefunc):
	frame = sys._current_frames()[tid]
	_setTraceFuncOnFrames(frame, tracefunc)
	tstate = getThreadState(frame)
	
	if tracefunc is None:
		_setTraceOfThread(tstate, Py_tracefunc(), PPyObject())
	else:
		_setTraceOfThread(tstate, c_tracefunc_trampoline, PPyObject_FromObj(tracefunc))
		
def setGlobalTraceFunc(tracefunc):
	# ensures _Py_TracingPossible > 0
	# sets tstate.c_tracefunc = call_trampoline
	# see PyEval_SetTrace in ceval.c
	# see sys_settrace in sysmodule.c
	sys.settrace(tracefunc)

	myframe = sys._getframe()
	tstate = getThreadState(myframe)
	c_traceobj = tstate.c_traceobj
	assert getPPyObjectPtr(tstate.c_traceobj) == id(tracefunc)

	mythread = thread.get_ident()
	frames = sys._current_frames()
	for t,frame in frames.iteritems():
		if t == mythread: continue
		setTraceOfThread(t, tracefunc)

#setGlobalTraceFunc(tracefunc)

def pdbIntoRunningThread(tid):
	from pdb import Pdb
	#from IPython.Debugger import Pdb
	
	pdb = Pdb()
	pdb.reset()
	
	import threading
	injectEvent = threading.Event()
	
	def inject_tracefunc(frame,ev,arg):
		injectEvent.set()
		pdb.interaction(frame, None)
		return pdb.trace_dispatch
	
	sys.settrace(dummytracer) # set some dummy. required by setTraceOfThread

	# go into loop. in some cases, it doesn't seem to work for some reason...
	while not injectEvent.isSet():
		setTraceOfThread(tid, inject_tracefunc)
	
		# Wait until we got into the inject_tracefunc.
		# This may be important as there is a chance that some of these
		# objects will get freed before they are used. (Which is probably
		# some other refcounting bug somewhere.)
		injectEvent.wait(1)

def main():
	def threadfunc(i):
		while True:
			for i in xrange(1000): pass
			time.sleep(1)
	
	threads = map(lambda i: thread.start_new_thread(threadfunc, (i,)), range(1))
	while True:
		if all(t in sys._current_frames() for t in threads): break	
	print "threads:", threads

	pdbThread = threads[0]
	pdbIntoRunningThread(pdbThread)

	while True:
		if pdbThread not in sys._current_frames().keys():
			print "thread exited"
			break
		#frames = sys._current_frames()
		#for t in threads:
		#	frame = frames[t]
			#print "tick counter of top frame in thread", t, ":", getTickCounter(frame)			
			#print " and trace func:", frame.f_trace
		time.sleep(1)

if __name__ == '__main__':
	main()
