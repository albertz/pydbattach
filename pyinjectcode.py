print "Hello from pyinjectcode:", __file__

import os, os.path, sys
sys.path += [os.path.dirname(__file__)]

import sys, thread
threads = [t for t in sys._current_frames().keys() if t != thread.get_ident()]

print "pyinjectcode found threads:", threads
assert threads, "fatal, no threads found"

tid = max(threads) # well, stupid, just made up, but in my case this seems to be the main thread :P
print "attaching to thread", tid

import pythreadhacks
pythreadhacks.pdbIntoRunningThread(tid)
