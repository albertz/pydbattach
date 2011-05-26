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

-- Albert Zeyer, <http://www.az2000.de>
