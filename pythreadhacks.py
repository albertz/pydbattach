import ctypes
import _ctypes

pyapi = ctypes.pythonapi
PyObj_FromPtr = _ctypes.PyObj_FromPtr

#f = pyapi._PyThread_CurrentFrames()
#f = PyObj_FromPtr(f)

#print f

import thread, time, sys

def threadfunc(i):
	while True:
		for i in xrange(1000): pass
		time.sleep(1)

threads = map(lambda i: thread.start_new_thread(threadfunc, (i,)), range(4))
while True:
	if all(t in sys._current_frames() for t in threads): break	
print "threads:", sys._current_frames()

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
	return tracefunc

# force _Py_TracingPossible > 0
sys.settrace(tracefunc)

import pythonhdr
from pythonhdr import PyObject, Py_ssize_t
CO_MAXBLOCKS = 20 # from Python/Include/code.h
POINTER = ctypes.POINTER
PPyObject = POINTER(PyObject)
c_int, c_long = ctypes.c_int, ctypes.c_long

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

def getTickCounter(frame):
	frame = PyFrameObject.from_address(id(frame))
	tstate = frame.f_tstate.contents
	return tstate.tick_counter

def setTraceOfThread(t):
	
	#PyObject *temp = tstate->c_traceobj;
	#tstate->c_tracefunc = NULL;
	#tstate->c_traceobj = NULL;
	#/* Must make sure that profiling is not ignored if 'temp' is freed */
	#tstate->use_tracing = tstate->c_profilefunc != NULL;
	#Py_XDECREF(temp);
	#tstate->c_tracefunc = func;
	#tstate->c_traceobj = arg;
	#/* Flag that tracing or profiling is turned on */
	#tstate->use_tracing = ((func != NULL) || (tstate->c_profilefunc != NULL));
	pass

def main():
	while True:
		frames = sys._current_frames()
		for t in threads:
			frame = frames[t]
			print "tick counter of frame", id(frame), ":", getTickCounter(frame)
			
			#frame.f_trace = tracefunc
		time.sleep(1)
main()
