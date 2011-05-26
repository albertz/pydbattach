print "injecting ..."
from ctypes import *
m = CDLL("pyinjectcode.dylib")
m.inject()

print "injecting done, sleeping"
import time
time.sleep(10)

print "done, exit"
