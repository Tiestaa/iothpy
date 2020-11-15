#! /usr/bin/python3
import sys
import pycoxnet
import re
import threading

def handle(connfd):
    print("got new conn {0}, {1}".format(connfd, threading.get_ident()))
    while(True):
        message = pycoxnet.recv(connfd, 1024)
        message = "ciao"
        if(message):
            print("tid {0} GOT: {1}".format(threading.get_ident(), message))
            pycoxnet.send(connfd, message)
        else:
            print("close conn {0} tid {1}".format(connfd, threading.get_ident()))
            pycoxnet.close(connfd)
            break
    return

def server(fd):
    while True:
        print("here")
        connfd = pycoxnet.accept(fd, 0, 0)
        if(connfd < 0):
            print("error accept")
            return
        x = threading.Thread(target=handle, args=(connfd,), daemon=True)
        x.start()
        print("after thread")
    return

def main():
    if(len(sys.argv) != 5):
        name = sys.argv[0]
        print("Usage: {0} vde_net addr prefix client_addr port\ne,g: {1} vxvde://234.0.0.1 10.0.0.20 24 10.0.0.10 5000\n\n".format(name, name))
        return 1

    stack = pycoxnet.stack(sys.argv[1])

    prefix = int(re.search(r'\d+', sys.argv[3]).group())
    port = int(re.search(r'\d+', sys.argv[4]).group())

    print(port)

    ifindex = stack.if_nametoindex("vde0")

    try:
        addr = pycoxnet.inet_pton(pycoxnet.AF_INET, sys.argv[2])
    except OSError:
        print("invalid ip addr")
    
    try:
        stack.ipaddr_add(pycoxnet.AF_INET, addr, prefix, ifindex)
    except Exception as e:
        print(e)

    fd = stack.msocket(pycoxnet.AF_INET, pycoxnet.SOCK_STREAM, 0)
    if(fd < 0):
        return 1

    if(pycoxnet.bind(fd, pycoxnet.AF_INET, port, "") <0):
        raise Exception("couldn't bind")

    pycoxnet.listen(fd, 5)
    server(fd)
    return;


    


if __name__ == "__main__":
    main()