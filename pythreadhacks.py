import ctypes
import _ctypes

pyapi = ctypes.pythonapi
PyObj_FromPtr = _ctypes.PyObj_FromPtr

import thread, time, sys

def threadfunc(i):
	while True:
		for i in xrange(1000): pass
		time.sleep(1)

threads = map(lambda i: thread.start_new_thread(threadfunc, (i,)), range(1))
while True:
	if all(t in sys._current_frames() for t in threads): break	
print "threads:", threads

mainthread = thread.get_ident()

def find_thread(frame):
	for t,f in sys._current_frames().items():
		while f is not None:
			if f == frame: return t
			f = f.f_back
	return None

def tracefunc(frame,ev,arg):
	thread = find_thread(frame)
	if thread == mainthread: pass
	else:
		print "trace", ev, "from thread", thread
		pass
	return tracefunc



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

def getThreadState(frame):
	frame = PyFrameObject.from_address(id(frame))
	tstate = frame.f_tstate.contents
	return tstate

def getTickCounter(frame):
	return getThreadState(frame).tick_counter
	
def setTraceOfThread(tstate, func, arg):
	assert type(tstate) is PyThreadState
	assert type(func) is Py_tracefunc
	assert type(arg) is PPyObject
	
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

def getPPyObjectPtr(pyobj):
	if not pyobj: return 0
	return _ctypes.addressof(pyobj.contents)


	
def setGlobalTraceFunc(tracefunc):
	# ensures _Py_TracingPossible > 0
	# sets tstate.c_tracefunc = call_trampoline
	# see PyEval_SetTrace in ceval.c
	# see sys_settrace in sysmodule.c
	sys.settrace(tracefunc)

	myframe = sys._getframe()
	tstate = getThreadState(myframe)
	
	c_tracefunc_trampoline = tstate.c_tracefunc
	c_traceobj = tstate.c_traceobj

	assert getPPyObjectPtr(c_traceobj) == id(tracefunc)

	mythread = thread.get_ident()
	frames = sys._current_frames()
	for t,frame in frames.iteritems():
		frame.f_trace = tracefunc
		tstate = getThreadState(frame)
		setTraceOfThread(tstate, c_tracefunc_trampoline, c_traceobj)

setGlobalTraceFunc(tracefunc)


def main():
	while True:
		frames = sys._current_frames()
		for t in threads:
			frame = frames[t]
			print "tick counter of top frame in thread", t, ":", getTickCounter(frame)			
			print " and trace func:", frame.f_trace
		time.sleep(1)
main()
