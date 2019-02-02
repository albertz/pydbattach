
import sys
import os

# Note: This is outdated now.
# See here for a more recent version:
# https://github.com/albertz/background-zmq-ipython

def initIPythonKernel():
  # You can remotely connect to this kernel. See the output on stdout.
  # See:
  # http://stackoverflow.com/questions/29148319/provide-remote-shell-for-python-script
  # https://github.com/ipython/ipython/issues/8097
  try:
    import IPython.kernel.zmq.ipkernel
    from IPython.kernel.zmq.ipkernel import Kernel
    from IPython.kernel.zmq.heartbeat import Heartbeat
    from IPython.kernel.zmq.session import Session
    from IPython.kernel import write_connection_file
    import zmq
    from zmq.eventloop import ioloop
    from zmq.eventloop.zmqstream import ZMQStream
    IPython.kernel.zmq.ipkernel.signal = lambda sig, f: None  # Overwrite.
  except ImportError, e:
    print "IPython import error, cannot start IPython kernel. %s" % e
    return
  import atexit
  import socket
  import logging
  import threading

  # Do in mainthread to avoid history sqlite DB errors at exit.
  # https://github.com/ipython/ipython/issues/680
  assert isinstance(threading.currentThread(), threading._MainThread)
  try:
    connection_file = "kernel-%s.json" % os.getpid()
    def cleanup_connection_file():
      try:
        os.remove(connection_file)
      except (IOError, OSError):
        pass
    atexit.register(cleanup_connection_file)

    logger = logging.Logger("IPython")
    logger.addHandler(logging.NullHandler())
    session = Session(username=u'kernel')

    context = zmq.Context.instance()
    ip = socket.gethostbyname(socket.gethostname())
    transport = "tcp"
    addr = "%s://%s" % (transport, ip)
    shell_socket = context.socket(zmq.ROUTER)
    shell_port = shell_socket.bind_to_random_port(addr)
    iopub_socket = context.socket(zmq.PUB)
    iopub_port = iopub_socket.bind_to_random_port(addr)
    control_socket = context.socket(zmq.ROUTER)
    control_port = control_socket.bind_to_random_port(addr)

    hb_ctx = zmq.Context()
    heartbeat = Heartbeat(hb_ctx, (transport, ip, 0))
    hb_port = heartbeat.port
    heartbeat.start()

    shell_stream = ZMQStream(shell_socket)
    control_stream = ZMQStream(control_socket)

    kernel = Kernel(session=session,
                    shell_streams=[shell_stream, control_stream],
                    iopub_socket=iopub_socket,
                    log=logger)

    write_connection_file(connection_file,
                          shell_port=shell_port, iopub_port=iopub_port, control_port=control_port, hb_port=hb_port,
                          ip=ip)

    print "To connect another client to this IPython kernel, use:", \
          "ipython console --existing %s" % connection_file
  except Exception, e:
    print "Exception while initializing IPython ZMQ kernel. %s" % e
    return

  def ipython_thread():
    kernel.start()
    try:
      ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
      pass

  thread = threading.Thread(target=ipython_thread, name="IPython kernel")
  thread.daemon = True
  thread.start()
