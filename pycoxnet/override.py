"""Override module

This module defines the function override_socket_module to allow
the use of the built-in socket module with a custom networking stack.

See help("pycoxnet.override_socket_module") for more information.
"""

from pycoxnet.msocket import MSocket
from pycoxnet.stack import Stack
import pycoxnet._pycoxnet as _pycoxnet

def override_socket_module(stack):
    """Override built-in socket module so that it creates sockets on the specified stack

    Parameters:
    -----------
    stack : Stack
       on success all the socket created using the built-in socket module will now 
       be created on this stack instead of using the default kernel stack
    """

    if not isinstance(stack, Stack):
        raise TypeError("stack must be of type Stack")

    import socket as socket_module

    # Create a new class that subclasses MSocket fixing the stack parameter
    # to provide an interface identical to the built-in socket class
    class socket(MSocket):
        def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
           MSocket.__init__(self, stack, family, type, proto, fileno)

    # Override the socket class
    socket_module.__dict__["socket"] = socket

    # Override defaulttimmeout functions
    socket_module.__dict__["getdefaulttimeout"] = _pycoxnet.getdefaulttimeout
    socket_module.__dict__["setdefaulttimeout"] = _pycoxnet.setdefaulttimeout

