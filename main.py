#!/usr/bin/python

import better_exchook
better_exchook.install()

import sys	
import vtrace
vtrace.exc_handler = sys.excepthook
vtrace.interact(int(sys.argv[1]))

