print "Hello World from pyinjectcode"

import pythreadhacks

import sys, thread
threads = [t for t in sys._current_frames().keys() if t != thread.get_ident()]

print "pyinjectcode found threads:", threads

assert threads, "fatal, no threads found"

print "attaching to first thread ..."
tid = threads[0]
pythreadhacks.pdbIntoRunningThread(tid)

