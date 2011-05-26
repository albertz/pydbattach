"""

Cobra's distributed code module capable of allowing
serialization of code from one system to another.

Particularly useful for clustering and workunit stuff.

"""
import os
import sys
import imp
import cobra

class DcodeFinder(object):

    def find_module(self, fullname, path=None):
        fobj, filename, typeinfo = imp.find_module(fullname, path)
        if os.path.isdir(filename):
            filename = os.path.join(filename, "__init__.py")

        if not os.path.exists(filename):
            return None

        fbytes = file(filename, "rb").read()
        fbytes = fbytes.replace("\r\n","\n")
        return DcodeLoader(fbytes, filename, typeinfo)

class DcodeLoader(object):

    def __init__(self, fbytes, filename, typeinfo):
        object.__init__(self)
        self.fbytes = fbytes
        self.filename = filename
        self.typeinfo = typeinfo

    def load_module(self, fullname):
        mod = sys.modules.get(fullname)
        if mod == None:
            mod = imp.new_module(fullname)
            sys.modules[fullname] = mod
            mod.__file__ = self.filename
            mod.__loader__ = self

            exec self.fbytes in mod.__dict__

        return mod

class DcodeImporter(object):

    def __init__(self, uri):
        object.__init__(self)
        if not cobra.isCobraUri(uri):
            raise ImportError
        try:
            self.cobra = cobra.CobraProxy(uri)
        except Exception, e:
            raise ImportError

    def find_module(self, fullname, path=None):
        return self.cobra.find_module(fullname, path)

def enableDcodeClient():
    """
    Once having called this, a client will be able to add cobra URIs
    to sys.path (one will be added automatically for the optional
    server parameter) and code will be imported via the distributed method.
    """
    if DcodeImporter not in sys.path_hooks:
        sys.path_hooks.append(DcodeImporter)

def addDcodeServer(server, port=None, override=False, ssl=False):
    scheme = "cobra"
    if ssl:
        scheme = "cobrassl"

    if port == None:
        port = cobra.COBRA_PORT

    uri = "%s://%s:%d/DcodeServer" % (scheme, server, port)
    if uri not in sys.path:
        if override:
            sys.path.insert(0, uri)
        else:
            sys.path.append(uri)

def enableDcodeServer():
    cobra.shareObject(DcodeFinder(), "DcodeServer")

