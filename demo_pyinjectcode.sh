#!/bin/bash

set -o monitor
./dummy-python-proc.py &
pypid=$!

{
	echo 'set $m = (void*)dlopen("./pyinjectcode.dylib", 8)'
	echo 'set $f = (void*)dlsym($m, "inject")'
	echo 'call (int)$f()'
	echo 'quit'
} | gdb /usr/bin/python $pypid

fg

