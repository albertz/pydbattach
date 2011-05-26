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
sleep 1 # to wait that Python has started up

./pydbattach.sh $pypid

fg

