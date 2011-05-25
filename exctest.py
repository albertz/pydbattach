#!/usr/bin/python

import sys
import linecache
filelines = linecache.getlines(__file__)

import re
exctestlines = [ re.sub("^if i == [0-9]+: ", "", l.strip()) for l in filelines if l.strip().startswith("if i == ") ]

i = 0
while True:	
	try:
		if i == 0: bla
		if i == 1: raise RuntimeException
		if i == 2: assert False
		if i == 3: pass
		if i == 4: break
	except:
		print sys.exc_info()[0].__name__, "handled", i, ":", exctestlines[i]
	else:
		print "no exception for", i, ":", exctestlines[i]
	i += 1
	