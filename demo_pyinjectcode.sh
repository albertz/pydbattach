#!/bin/bash

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

