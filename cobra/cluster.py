
"""
Cobra's built in clustering framework
"""

import sys
import time
import cobra
import dcode
import Queue
import struct
import socket
import threading
import subprocess

cluster_port = 32123
cluster_ip = "224.69.69.69"

sub_cmd = """
import cobra.cluster
import cobra.dcode
import urllib2
if %s:
    x = urllib2.Request("%s")
    cobra.dcode.enableDcodeClient()
    cobra.dcode.addDcodeServer(x.get_host().split(":")[0])
cobra.cluster.getAndDoWork("%s")
"""

class ClusterWork(object):
    """
    Extend this object to create your own work units.  Do it in
    a proper module (and not __main__ to be able to use this
    in conjunction with cobra.dcode).
    """
    def __init__(self):
        object.__init__(self)

    def work(self):
        """
        Actually do the work associated with this work object.
        """
        print "OVERRIDE ME"

    def done(self):
        """
        This is called back on the server once a work unit
        is complete and returned.
        """
        print "OVERRIDE DONE"

class ClusterServer:
    def __init__(self, name, maxsize=0, docode=False):
        self.added = False
        self.name = name
        self.inprog = 0
        self.maxsize = maxsize
        self.queue = Queue.Queue(maxsize)
        self.cobraname = cobra.shareObject(self)
        if docode: dcode.enableDcodeServer()

    def runServer(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while (self.added == False or
               self.queue.empty() == False or
               self.inprog > 0):
            buf = "cobra:%s:%s:%d" % (self.name, self.cobraname, cobra.COBRA_PORT)
            sock.sendto(buf, (cluster_ip, cluster_port))
            time.sleep(1)

    def addWork(self, work):
        """
        Add a work object to the ClusterServer.  This 
        """
        self.added = True # One time add detection
        if not isinstance(work, ClusterWork):
            raise Exception("%s is not a ClusterWork extension!")
        self.queue.put(work)

    def getWork(self):
        try:
            ret = self.queue.get_nowait()
            self.inprog += 1
            return ret
        except Queue.Empty, e:
            return None

    def doneWork(self, work):
        """
        Used by the clients to report work as done.
        """
        self.inprog -= 1
        work.done()

class ClusterClient:

    """
    Listen for our name (or any name if name=="*") on the cobra cluster
    multicast address and if we find a server in need, go help.

    maxwidth is the number of work units to do in parallel
    docode will enable code sharing with the server
    threaded == True will use threads, otherwise subprocess of the python interpreter (OMG CLUSTER)
    """

    def __init__(self, name, maxwidth=4, threaded=True, docode=False):
        self.go = True
        self.name = name
        self.width = 0
        self.maxwidth = maxwidth
        self.threaded = threaded
        self.verbose = False
        self.docode = docode

        if docode: dcode.enableDcodeClient()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("",cluster_port))
        mreq = struct.pack("4sL", socket.inet_aton(cluster_ip), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def processWork(self):
        """
        Runs handing out work up to maxwidth until self.go == False.
        """
        while self.go:
            
            buf, sockaddr = self.sock.recvfrom(4096)
            if self.width >= self.maxwidth:
                continue

            if not buf.startswith("cobra:") and not buf.startswith("cobrassl:"):
                continue

            info = buf.split(":")
            if len(info) != 4:
                continue

            server, svrport = sockaddr
            cc,name,cobject,portstr = info
            if (self.name != name) and (self.name != "*"):
                continue

            port = int(portstr)

            #FIXME this should fire a thread...
            if self.docode:
                dcode.addDcodeServer(server, port=port)

            uri = "%s://%s:%d/%s" % (cc,server,port,cobject)
            self.fireRunner(uri)

    def fireRunner(self, uri):
        if self.threaded:
            thr = threading.Thread(target=self.threadWorker, args=(uri,))
            thr.setDaemon(True)
            thr.start()
        else:
            thr = threading.Thread(target=self.threadForker, args=(uri,))
            thr.setDaemon(True)
            thr.start()

    def threadWorker(self, uri):
        self.width += 1
        try:
            return getAndDoWork(uri)
        finally:
            self.width -= 1

    def threadForker(self, uri):
        self.width += 1
        cmd = sub_cmd % (self.docode, uri, uri)
        try:
            sub = subprocess.Popen([sys.executable, '-c', cmd])
            sub.wait()
        finally:
            self.width -= 1

def getAndDoWork(uri):
    proxy = cobra.CobraProxy(uri)
    work = proxy.getWork()
    # If we got work, do it.
    if work != None:
        work.work()
        proxy.doneWork(work)

