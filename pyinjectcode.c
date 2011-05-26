/*
 compile:
 gcc -g -I /System/Library/Frameworks/Python.framework/Headers -framework Python -dynamiclib pyinjectcode.c -o pyinjectcode.dylib
 */

#include "Python.h"
#include "pythread.h"
#include "stringobject.h"
#include <string.h>
#include <stdio.h>

static char filename[FILENAME_MAX] = "";

static PyObject *
builtin_execfile()
{
	PyObject *globals = NULL, *locals = NULL, *builtins = NULL;
	PyObject *res;
	FILE* fp = NULL;
	PyCompilerFlags cf;
	int exists;
	
	globals = PyDict_New();
	locals = globals;
	builtins = PyEval_GetBuiltins();
	
	if (PyDict_SetItemString(globals, "__builtins__",
							 builtins) != 0)
		return NULL;
	
	if (PyDict_SetItemString(globals, "__file__",
							 PyString_FromString(filename)) != 0)
		return NULL;
	
	exists = 0;
	/* Test for existence or directory. */
#if defined(PLAN9)
	{
		Dir *d;
		
		if ((d = dirstat(filename))!=nil) {
			if(d->mode & DMDIR)
				werrstr("is a directory");
			else
				exists = 1;
			free(d);
		}
	}
#elif defined(RISCOS)
	if (object_exists(filename)) {
		if (isdir(filename))
			errno = EISDIR;
		else
			exists = 1;
	}
#else   /* standard Posix */
	{
		struct stat s;
		if (stat(filename, &s) == 0) {
			if (S_ISDIR(s.st_mode))
#if defined(PYOS_OS2) && defined(PYCC_VACPP)
				errno = EOS2ERR;
#else
			errno = EISDIR;
#endif
			else
				exists = 1;
		}
	}
#endif
	
	if (exists) {
		Py_BEGIN_ALLOW_THREADS
		fp = fopen(filename, "r" PY_STDIOTEXTMODE);
		Py_END_ALLOW_THREADS
		
		if (fp == NULL) {
			exists = 0;
		}
	}
	
	if (!exists) {
		PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
		return NULL;
	}
	cf.cf_flags = 0;
	if (PyEval_MergeCompilerFlags(&cf))
		res = PyRun_FileExFlags(fp, filename, Py_file_input, globals,
								locals, 1, &cf);
	else
		res = PyRun_FileEx(fp, filename, Py_file_input, globals,
						   locals, 1);
	return res;
}


struct bootstate {
	PyInterpreterState *interp;
};

static void
t_bootstrap(void *boot_raw)
{
	struct bootstate *boot = (struct bootstate *) boot_raw;
	PyThreadState *tstate;
	PyObject *res;
	
	tstate = PyThreadState_New(boot->interp);
	if (tstate == NULL) {
		PyMem_DEL(boot_raw);
		PySys_WriteStderr("pyinjectcode: Not enough memory to create thread state.\n");
		PyErr_PrintEx(0);
		return;
	}
	
	tstate->thread_id = PyThread_get_thread_ident();
	PyEval_AcquireThread(tstate);
	
	PySys_WriteStderr("pyinjectcode: Executing %s.\n", filename);
	res = builtin_execfile();
	if (res == NULL) {
		if (PyErr_ExceptionMatches(PyExc_SystemExit))
			PyErr_Clear();
		else {
			PySys_WriteStderr("pyinjectcode: Unhandled exception in thread.\n");
			PyErr_PrintEx(0);
			PyErr_Clear(); // clear state, we don't want to crash the other process
		}
	}
	else
		Py_DECREF(res);
	
	PySys_WriteStderr("pyinjectcode: Thread finished execution.\n");
	PyMem_DEL(boot_raw);
	PyThreadState_Clear(tstate);
	PyThreadState_DeleteCurrent();
	PyThread_exit_thread();
}


int startthread() {
	struct bootstate *boot;
	long ident;
	
	boot = PyMem_NEW(struct bootstate, 1);
	if (boot == NULL) {
		PySys_WriteStderr("no memory for bootstate\n");
		PyErr_PrintEx(0);
		return 1;
	}
	
	PyThread_init_thread(); // if not yet done
	PyEval_InitThreads(); /* Start the interpreter's thread-awareness */
	
	// XXX this fails ??
	//boot->interp = PyThreadState_Get()->interp;
	boot->interp = PyInterpreterState_Head();
	
	ident = PyThread_start_new_thread(t_bootstrap, (void*) boot);
	if (ident == -1) {
		PyMem_DEL(boot);
		PySys_WriteStderr("no memory for thread\n");
		PyErr_PrintEx(0);
		return 1;
	}
	return 0;
}


int inject(char* fn) {
	strcpy(filename, fn);
	return startthread();
}

