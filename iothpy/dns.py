"""
DNS module

This module defines the DNS class used to create the ioth dns.

All methods of this class are:
... TODO
"""
# C-like struct definition
    
class sockaddr(object):
    
    __slots__ = ('sa_family', 'sa_data')

    def __init__(self, sa_family, sa_data):
        self.sa_family = sa_family
        self.sa_data = sa_data

    def __setattr__(self, name, value):
        if name not in self.__slots__:
            raise AttributeError("object has no attribute '{}'".format(name))
        else:
            check_type = None; 
            match name:
                case "sa_family":
                    check_type = int
                case "sa_data":
                    check_type = str
            if (value != None and not isinstance(value,check_type)):
                raise TypeError("{} must be of type {}".format(name,check_type.__name__))
            else:
                super().__setattr__(name,value)
                
    @property
    def __dict__(self):
        return {
            s: getattr(self, s)
            for s in {
                s
                for cls in type(self).__mro__
                for s in getattr(cls, '__slots__', ())
            }
            if hasattr(self, s)
        }
 

class addrinfo(object):

    __slots__ = ('ai_flags', 'ai_family', 'ai_socktype', 'ai_protocol' , 'ai_addrlen', 'ai_addr', 'ai_canonname')

    def __init__(self, ai_flags:int = None, ai_family:int = None, ai_socktype:int = None, 
        ai_protocol:int = None, ai_addrlen:int = None, ai_addr:sockaddr = None, ai_canonname = None):
        self.ai_flags = ai_flags
        self.ai_family = ai_family
        self.ai_socktype = ai_socktype
        self.ai_protocol = ai_protocol
        self.ai_addrlen = ai_addrlen
        self.ai_addr = ai_addr
        self.ai_canonname = ai_canonname
    
    @property
    def __dict__(self):
        return {
            s: getattr(self, s)
            for s in {
                s
                for cls in type(self).__mro__
                for s in getattr(cls, '__slots__', ())
            }
            if hasattr(self, s)
        }

    def __setattr__(self, name, value):
        if name not in self.__slots__:
            raise AttributeError("object has no attribute '{}'".format(name))
        else:
            check_type = None; 
            match name:
                case "ai_flags" | "ai_family" | "ai_socktype" | "ai_protocol" | "ai_addrlen":
                    check_type = int
                case "ai_addr":
                    check_type = sockaddr
                case "ai_canonname":
                    check_type = str
            if (value != None and not isinstance(value,check_type)):
                raise TypeError("{} must be of type {}".format(name,check_type.__name__))
            else:
                super().__setattr__(name,value)

#Import iothpy c module
from . import _iothpy

class DNS(_iothpy.DNSBase):
    def __init__(self, *arg, **kwarg):
        # Pass all arguments to the base class constructor
       _iothpy.DNSBase.__init__(self, *arg, **kwarg)
    
    def getaddrinfo(self, *arg):
        (addrinfos, code, address) = _iothpy.DNSBase.getaddrinfo(self, *arg)
        listInfos = []
        for addinfo in addrinfos:
            tmpSockAddr = sockaddr(addinfo["ai_addr"]["sa_family"], addinfo["ai_addr"]["sa_data"])
            listInfos.append(addrinfo(addinfo["ai_flags"], addinfo["ai_family"], addinfo["ai_socktype"], 
                addinfo["ai_protocol"], addinfo["ai_addrlen"], tmpSockAddr, addinfo["ai_canonname"]))

        return (listInfos, code, address)

# pathtag const initialization
IOTHDNS_HOSTS = 0
IOTHDNS_SERVICES = 1