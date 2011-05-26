#!/bin/bash

pid=$1

[ "$pid" = "" ] && \
	echo "usage: $0 <pid>" && exit 1

bin=$(ps -p $pid -o command | tail -n1 | sed "s/ .*$//")

[ \! -x $bin ] && \
	bin=$(type $bin | sed "s/$bin is//")

[ \! -x $bin ] && \
	echo "didn't found binary for process $pid" >&2 && exit 1

cd "$(dirname "$0")"
mydir="$(pwd)"

dylib="$mydir/pyinjectcode.dylib"
[ \! -e "$dylib" ] && dylib="$mydir/pyinjectcode.so"
[ \! -e "$dylib" ] && dylib="$mydir/pyinjectcode.dll"
[ \! -e "$dylib" ] && \
	echo "pyinjectcode.{dylib,so,dll} not found." >&2 && \
	echo "compile the library first." >&2 && exit 1

pycode="$mydir/pyinjectcode.py"

{
	echo "set \$m = (void*)dlopen(\"$dylib\", 8)"
	echo 'set $f = (void*)dlsym($m, "inject")'
	echo "call (int)\$f(\"$pycode\")"
	echo 'quit'
} | gdb $bin $pid

echo "done, you should have a Pdb shell in the Python process now"
