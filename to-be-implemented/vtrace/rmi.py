"""
Cobra integration for remote debugging
"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import md5
import os
import socket

import vtrace
import cobra

callback_daemon = None

def getTracerFactory():
    """
    Return a TracerFactory proxy object from the remote server
    """
    return cobra.CobraProxy("cobra://%s:%d/TracerFactory" % (vtrace.remote, vtrace.port))

class TraceProxyFactory:
    """
    A "factory" object for creating tracers and
    wrapping them up in a proxy instance to the
    *local* server.  This object is shared out
    via the pyro server for vtrace clients.
    """
    def getTrace(self):
        trace = vtrace.getTrace()
        host,port = cobra.getLocalInfo()
        unique = md5.md5(os.urandom(20)).hexdigest()
        vtrace.cobra_daemon.shareObject(trace, unique)
        trace.proxy = cobra.CobraProxy("cobra://%s:%d/%s" % (host,port,unique))
        return unique

    def releaseTrace(self, proxy):
        """
        When a remote system is done with a trace
        and wants the server to clean him up, hand
        the proxy object to this.
        """
        vtrace.cobra_daemon.unshareObject(proxy.__dict__.get("__cobra_name", None))

class RemoteTrace(cobra.CobraProxy):

    def __init__(self, *args, **kwargs):
        cobra.CobraProxy.__init__(self, *args, **kwargs)

def getCallbackProxy(trace, notifier):
    """
    Get a proxy object to reference *notifier* from the
    perspective of *trace*.  The trace is specified so
    we may check on our side of the connected socket to
    give him the best possible ip address...
    """
    global callback_daemon
    port = getCallbackPort()
    host, nothing = cobra.getCobraSocket(trace).getSockName()
    unique = md5.md5(os.urandom(20)).hexdigest()
    callback_daemon.shareObject(notifier, unique)
    return cobra.CobraProxy("cobra://%s:%d/%s" % (host, port, unique))

def getCallbackPort():
    """
    If necessary, start a callback daemon.  Return the
    ephemeral port it was bound on.
    """
    global callback_daemon
    if callback_daemon == None:
        callback_daemon = cobra.CobraDaemon(port=0)
        callback_daemon.fireThread()
    return callback_daemon.port

def startCobraDaemon():
    if vtrace.cobra_daemon == None:
        vtrace.cobra_daemon = cobra.CobraDaemon(port=vtrace.port)
        vtrace.cobra_daemon.fireThread()

def getRemoteTrace():
    factory = getTracerFactory()
    unique = factory.getTrace()
    return RemoteTrace("cobra://%s:%d/%s" % (vtrace.remote, vtrace.port, unique))

def startVtraceServer():
    """
    Fire up the pyro server and share out our
    "trace factory"
    """
    startCobraDaemon()
    factory = TraceProxyFactory()
    vtrace.cobra_daemon.shareObject(factory, "TracerFactory")
