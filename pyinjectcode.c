#include "Python.h"
#include "pythread.h"

static PyObject *
builtin_execfile()
{
    char *filename = "pyinjectcode.py";
    PyObject *globals = Py_None, *locals = Py_None;
    PyObject *res;
    FILE* fp = NULL;
    PyCompilerFlags cf;
    int exists;
	
    if (globals == Py_None) {
        globals = PyEval_GetGlobals();
        if (locals == Py_None)
            locals = PyEval_GetLocals();
    }
    else if (locals == Py_None)
        locals = globals;
    if (PyDict_GetItemString(globals, "__builtins__") == NULL) {
        if (PyDict_SetItemString(globals, "__builtins__",
                                 PyEval_GetBuiltins()) != 0)
            return NULL;
    }
	
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
#                               if defined(PYOS_OS2) && defined(PYCC_VACPP)
				errno = EOS2ERR;
#                               else
			errno = EISDIR;
#                               endif
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
    PyThreadState *tstate;
};

static void
t_bootstrap(void *boot_raw)
{
    struct bootstate *boot = (struct bootstate *) boot_raw;
    PyThreadState *tstate;
    PyObject *res;
	
    tstate = boot->tstate;
    tstate->thread_id = PyThread_get_thread_ident();
    _PyThreadState_Init(tstate);
    PyEval_AcquireThread(tstate);

	res = builtin_execfile();
    //res = PyEval_CallObjectWithKeywords(
	//									boot->func, boot->args, boot->keyw);
    if (res == NULL) {
        if (PyErr_ExceptionMatches(PyExc_SystemExit))
            PyErr_Clear();
        else {
            PyObject *file;
            PySys_WriteStderr(
							  "Unhandled exception in thread started by injection code");
            PySys_WriteStderr("\n");
            PyErr_PrintEx(0);
        }
    }
    else
        Py_DECREF(res);

    PyMem_DEL(boot_raw);
    PyThreadState_Clear(tstate);
    PyThreadState_DeleteCurrent();
    PyThread_exit_thread();
}


char* startthread() {
	boot = PyMem_NEW(struct bootstate, 1);
    if (boot == NULL)
        return "no memory";
    boot->interp = PyThreadState_GET()->interp;
    boot->tstate = _PyThreadState_Prealloc(boot->interp);
    if (boot->tstate == NULL) {
        PyMem_DEL(boot);
        return "no memory";
    }
    PyEval_InitThreads(); /* Start the interpreter's thread-awareness */
    ident = PyThread_start_new_thread(t_bootstrap, (void*) boot);
    if (ident == -1) {
        PyThreadState_Clear(boot->tstate);
        PyMem_DEL(boot);
        return "can't start new thread";
    }
	return NULL;
}


void inject() {
	char* err = startthread();
	if(err) {
		PySys_WriteStderr(err);
		PySys_WriteStderr("\n");
		PyErr_PrintEx(0);
	}
}

