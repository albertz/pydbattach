#!/usr/bin/python

import time, ctypes

pid = ctypes.pythonapi.getpid()

i = 0
while True:
	print("<" + str(pid) + ">", i)
	time.sleep(1)
	i += 1
