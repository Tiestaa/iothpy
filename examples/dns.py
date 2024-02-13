import iothpy

dnsNN = iothpy.DNS(None,None)

dnsC = iothpy.DNS(None, "search v2.cs.unibo.it cs.unibo.it\n"
			"nameserver 8.8.8.8")

stack = iothpy.Stack("vdestack", "vxvde://234.0.0.1")
stack.ioth_config("eth,ip=10.0.0.53/24,gw=10.0.0.1")


dnsSC = iothpy.DNS(stack, "pipposerver 1.1.1.1")

#dnsSC.setpath(iothpy.IOTHDNS_HOSTS, "/home/pippo")

#print(dnsSC.getpath(iothpy.IOTHDNS_HOSTS))

addinfos, code, address = dnsSC.getaddrinfo("1.1.1.1", None, None)

#print(code, address)

#dnsSC.freeaddrinfo(address)

print(dnsC.lookup_a("mad.cs.unibo.it", 1))
print(dnsC.lookup_aaaa("mad.cs.unibo.it", 4))
print(dnsC.lookup_aaaa_compat("mad.cs.unibo.it", 2))
print(dnsC.lookup_aaaa_compat("mad.cs.unibo.it", 1))
print(dnsC.lookup_aaaa_compat("mad.cs.unibo.it", 4))