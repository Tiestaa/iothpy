"""
DNS module

This module defines the DNS class used to create the ioth dns.

All methods of this class are:
... TODO
"""

#Import iothpy c module
from . import _iothpy

class DNS(_iothpy.DNSBase):
    def __init__(self, *arg, **kwarg):
        # Pass all arguments to the base class constructor
       _iothpy.DNSBase.__init__(self, *arg, **kwarg)

# pathtag const initialization
IOTHDNS_HOSTS = 0
IOTHDNS_SERVICES = 1