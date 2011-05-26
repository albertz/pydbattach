from ctypes import *
m = CDLL("pyinjectcode.dylib")

m.inject()
