#!/usr/bin/python

import better_exchook
better_exchook.install()
	
import vtrace
import sys
vtrace.interact(int(sys.argv[1]))

