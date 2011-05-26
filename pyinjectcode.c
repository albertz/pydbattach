/*
 compile:
 gcc -g -I /System/Library/Frameworks/Python.framework/Headers -framework Python -dynamiclib pyinjectcode.c -o pyinjectcode.dylib
 */

#include "Python.h"
#include "Python-ast.h"
#include "pythread.h"
#include "stringobject.h"
#include "eval.h"
#include "pyarena.h"
#include "code.h"
#include "compile.h"
#include <string.h>
#include <stdio.h>

static char filename[FILENAME_MAX] = "";

// from import.c
/* Parse a source file and return the corresponding code object */

static PyCodeObject *
parse_source_module(const char *pathname, FILE *fp)
{
    PyCodeObject *co = NULL;
    mod_ty mod;
    PyCompilerFlags flags;
    PyArena *arena = PyArena_New();
    if (arena == NULL)
        return NULL;
	
    flags.cf_flags = 0;
	
    mod = PyParser_ASTFromFile(fp, pathname, Py_file_input, 0, 0, &flags,
                               NULL, arena);
    if (mod) {
        co = PyAST_Compile(mod, pathname, NULL, arena);
    }
    PyArena_Free(arena);
    return co;
}


static PyObject* runPythonFile(FILE* fp, char* pathname) {
	
	PyCodeObject *co = parse_source_module(pathname, fp);
	if (co == NULL)
		return NULL;

	//PyObject *m = PyImport_ExecCodeModuleEx("<pyinjected module>", (PyObject *)co, pathname);
    
	PyObject *globals = PyDict_New();
	PyObject *locals = globals;
	
	if (PyDict_SetItemString(globals, "__builtins__",
							 PyEval_GetBuiltins()) != 0)
		return NULL;
	
	if (PyDict_SetItemString(globals, "__file__",
							 PyString_FromString(pathname)) != 0)
		return NULL;

	PyObject* v = PyEval_EvalCode((PyCodeObject *)co, globals, locals);
	
	Py_DECREF(co);
	
	//return m;
	return v;
}

static PyObject *
builtin_execfile()
{
	FILE* fp = NULL;
	int exists;
		
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
	
	return runPythonFile(fp, filename);
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

	PyGILState_STATE oldGILState = PyGILState_Ensure(); {
	
		boot->interp = PyThreadState_Get()->interp;	
		ident = PyThread_start_new_thread(t_bootstrap, (void*) boot);
	
	} PyGILState_Release(oldGILState);
	
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


int
injected_PyEval_SetTraceEx(PyThreadState* tstate, Py_tracefunc func, PyObject *arg)
{
	PyGILState_STATE oldGILState = PyGILState_Ensure(); {
		
		// code from original PyEval_SetTrace
		// also, like in the Python variant, we don't have access to _Py_TracingPossible here
	
		PyObject *temp = tstate->c_traceobj;
		Py_XINCREF(arg);
		tstate->c_tracefunc = NULL;
		tstate->c_traceobj = NULL;
		/* Must make sure that profiling is not ignored if 'temp' is freed */
		tstate->use_tracing = tstate->c_profilefunc != NULL;
		Py_XDECREF(temp);
		tstate->c_tracefunc = func;
		tstate->c_traceobj = arg;
		/* Flag that tracing or profiling is turned on */
		tstate->use_tracing = ((func != NULL)
							   || (tstate->c_profilefunc != NULL));
	
	} PyGILState_Release(oldGILState);
	
	return 0;
}

