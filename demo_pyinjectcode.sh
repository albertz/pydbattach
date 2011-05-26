#!/bin/bash

# This demo scripts starts some dummy Python process (dummy-python-proc.py).
#
# Then, via GDB, it dynamically loads a previously prepared library (pyinjectcode.c)
# and calls the function 'inject()' from it.
#
# The library pyinjectcode.c creates a new Python thread and runs
# the code from pyinjectcode.py.
#
# The Python code pyinjectcode.py uses some magic in pythreadhacks.py
# to attach with Pdb to the first other Python thread.

set -o monitor
./dummy-python-proc.py &
pypid=$!

dylib="pyinjectcode.dylib"
[ \! -e "$dylib" ] && dylib="pyinjectcode.so"
[ \! -e "$dylib" ] && dylib="pyinjectcode.dll"
[ \! -e "$dylib" ] && \
	echo "pyinjectcode.{dylib,so,dll} not found." && \
	echo "compile the library first." && exit 1

{
	echo "set \$m = (void*)dlopen(\"$dylib\", 8)"
	echo 'set $f = (void*)dlsym($m, "inject")'
	echo 'call (int)$f()'
	echo 'quit'
} | gdb /usr/bin/python $pypid

fg

