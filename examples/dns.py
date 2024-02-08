import iothpy

dnsNN = iothpy.DNS(None,None)

dnsC = iothpy.DNS(None, "nameserver 1.1.1.1")

stack = iothpy.Stack("vdestack", "vxvde://234.0.0.1")
stack.ioth_config("eth,ip=10.0.0.53/24,gw=10.0.0.1")


dnsSC = iothpy.DNS(stack, "nameserver 1.1.1.1")

dnsSC.setpath(iothpy.IOTHDNS_HOSTS, "/home/pippo")
print(dnsSC.getpath(iothpy.IOTHDNS_HOSTS))