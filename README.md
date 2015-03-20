pydbattach - attach to running Python process
=============================================

It probably should have been called pydbgattach or so but I didn't noticed until I went to bed so I keep this name now. :)

This works in several steps:

1. We are attaching to the running Python process and want to inject some C-code `pyinjectcode.c`.

    Originally I planned to develop a small tool for this by myself based on `ptrace`. For Mac, I also found `mach_inject` which may have been useful.

    However, to keep things simple for now, I just use GDB for this.

    See the file `pydbattach.sh` which basically does this step.

2. `pyinjectcode.c` creates a new Python thread and runs a Python script. In our case, it runs `pyinjectcode.py`.

3. `pyinjectcode.py` starts a Pdb instance and attaches it to another already running Python process (just the first it founds for now). This is done via a more generic `sys.settrace` function which is implemented in `pythreadhacks.py`.

4. `pythreadhacks.py` heavily uses `(_)ctypes` to access the underlying CPython objects for the thread state. This way, it reimplements `PyEval_SetTrace` in a more general way.

---

Similar alternatives, to attach to running CPython process without having it prepared beforehand. Those usually use the OS debugging capabilities (or use gdb/lldb) to attach to the native CPython process and then inject some code or just analyze the native CPython thread stacks.

* [pyringe](https://github.com/google/pyringe)
* [pyrasite](https://github.com/lmacken/pyrasite)
* [pystuck](https://github.com/alonho/pystuck)
* [pdb-clone](https://code.google.com/p/pdb-clone/wiki/RemoteDebugging)

There are other alternatives where you prepare your Python script beforehand to listen on some (tcp/file) socket to provide an interface for remote debugging and/or just a Python shell / REPL.

* [IPython](http://ipython.org/), by embedding an IPython kernel,
see [here](http://ipython.readthedocs.org/en/latest/interactive/reference.html#embedding),
[example remote shell code](https://github.com/albertz/pydbattach/blob/master/alternatives/ipython_remote_shell.py)
* [winpdb](http://winpdb.org/) (cross platform) remote debugger
* [PyCharm IDE](https://www.jetbrains.com/pycharm/) remote debugger,
[doc](https://www.jetbrains.com/pycharm/help/remote-debugging.html)
* [PyDev IDE](http://pydev.org/) remote debugger
* [Twisted Conch Manhole](https://twistedmatrix.com),
[official example](http://twistedmatrix.com/documents/current/_downloads/demo_manhole.tac),
[lothar.com example](http://www.lothar.com/tech/twisted/manhole.xhtml),
[lysator.liu.se example](http://www.lysator.liu.se/xenofarm/python/tmp-server/Twisted/doc/howto/manhole.html),
[related StackOverflow question](http://stackoverflow.com/questions/24296807/python-twisted-manhole-that-works-like-ipython-or-similar),
[blog.futurefoundries.com (2013)](http://blog.futurefoundries.com/2013/04/ssh-into-your-python-server.html)
* very simple [manhole](https://pypi.python.org/pypi/manhole), has also some overview over related projects
* [ispyd](https://github.com/GrahamDumpleton/ispyd)
* [Eric IDE](http://eric-ide.python-projects.org/)
* [Trepan (based on pydb)](https://github.com/rocky/python2-trepan)
* [rpdb](https://pypi.python.org/pypi/rpdb/)
* [rconsole](http://winpdb.org/2010/09/rconsole-remote-python-console/)
(part of [rfoo](http://code.google.com/p/rfoo/))

Some overviews and collected code examples:

* [(QGIS) Example code for PyDev, Winpdb, Eric](https://github.com/sourcepole/qgis-remote-debug)
* [Python Wiki: Python debugging tools](https://wiki.python.org/moin/PythonDebuggingTools),
[Python Wiki: Python debuggers](https://wiki.python.org/moin/PythonDebuggers)
* [StackOverflow question about Python remote shells.](http://stackoverflow.com/questions/29148319/provide-remote-shell-for-python-script)

-- Albert Zeyer, <http://www.az2000.de>
