print "injecting ..."
from ctypes import *
m = CDLL("pyinjectcode.dylib")
m.inject()

print "injecting done"

import time
time.sleep(1)
