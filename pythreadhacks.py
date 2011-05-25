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
		#for i in xrange(1000): pass
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

class cPyFrameObject(ctypes.py_object):
	_fields_ = [
		()
	]

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
			frame.f_trace = tracefunc
		time.sleep(1)
main()
