/* 
 * This file is part of the iothpy library: python support for ioth.
 * 
 * Copyright (c) 2020-2024   Dario Mylonopoulos
 *                           Lorenzo Liso
 *                           Francesco Testa
 * Virtualsquare team.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include "iothpy_dns.h"
#include "iothpy_stack.h"
#include "iothpy_socket.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/limits.h>

#define IS_PATH(str) (strchr(str, '/') != NULL)
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define GET_STRING_FLAG(flag, str) do {\
    if(flag & O_RDONLY) str = "r";\
    else if(flag & O_WRONLY) str = "w";\
    else if(flag & O_RDWR) str = "r+";\
    else if(flag & O_CREAT || flag & O_EXCL) str = "x";\
    else if(flag & O_TRUNC) str = "w+";\
    else if(flag & O_APPEND) str = "a";\
} while (0)

static void 
dns_dealloc(dns_object* self){
    if(PyObject_CallFinalizerFromDealloc((PyObject*)self) < 0) {
        return;
    }

    PyTypeObject* tp = Py_TYPE(self);
    tp->tp_free(self);
}

static PyObject* 
dns_repr(dns_object* self){
    return PyUnicode_FromFormat("<dns ojbect, stack=%p>", self->dns);
}

static PyObject*
dns__new__(PyTypeObject* type, PyObject* args, PyObject *kwargs){
    PyObject* new = type->tp_alloc(type, 0);

    dns_object* self = (dns_object*) new;

    if(self != NULL){
        self->dns = NULL;
    }
    return new;
}

static int
dns__init__(PyObject* self, PyObject* args, PyObject* kwds){
    
    dns_object* s = (dns_object*) self;

    char* config;
    PyObject* stackBase = NULL;
    struct ioth* stack = NULL;

    if(!PyArg_ParseTuple(args,"Oz", &stackBase, &config))
        return -1;


    if(stackBase != Py_None)
        stack = ((stack_object*) stackBase)->stack;

    if(config != NULL && !IS_PATH(config)){
        s->dns = iothdns_init_strcfg(stack, config);
    } else {
        /* config NULL or config is Path. iothdns_init handled both. */
        s->dns = iothdns_init(stack,config);
    }

    if(s->dns == NULL){
        PyErr_SetFromErrno(PyExc_SyntaxError);
        return -1;
    }

    return 0;
}

static void
dns__del__( dns_object* self ){
    
    /* save exception, if any */
    PyObject* exc = PyErr_GetRaisedException();

    /* delete iothdns */
    if(self->dns != NULL){
        iothdns_fini(self->dns);
        self->dns = NULL;
    }

    /* restore exception */
    if(exc)
        PyErr_SetRaisedException(exc);
}

PyDoc_STRVAR(dns_update_doc, "update(path_config)\n\
Update DNS configuration using a file (resolv.conf syntax)");

static PyObject* dns_update(dns_object* self, PyObject* args){
    
    char* path = NULL;
    
    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s", &path))
        return NULL;
    
    if(iothdns_update(self->dns,path) < 0){
        PyErr_SetFromErrno(PyExc_SyntaxError);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(dns_update_strcfg_doc, "update_strcfg(config)\n\
Update DNS configuration using a string");

static PyObject* dns_update_strcfg(dns_object* self, PyObject* args){
    
    char* config = NULL;
    
    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s", &config))
        return NULL;
    
    if(iothdns_update_strcfg(self->dns, config) < 0){
        PyErr_SetFromErrno(PyExc_SyntaxError);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(dns_setpath_doc,"setpath(pathtag, value)\n\
C library uses system provided files like /etc/hosts and /etc/services. \n\
Use this method to redefine files instead of using system provided ones");

static PyObject* dns_setpath(dns_object* self, PyObject* args){
    int pathtag = -1;
    char* newValue = NULL;

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "iz", &pathtag, &newValue))
        return NULL;

    if(pathtag != IOTHDNS_HOSTS && pathtag != IOTHDNS_SERVICES){
        PyErr_SetString(PyExc_SyntaxError, "invalid pathtag value");
        return NULL;
    }

    iothdns_setpath(self->dns, pathtag, newValue);

    Py_RETURN_NONE;
}

PyDoc_STRVAR(dns_getpath_doc,"getpath(pathtag)\n\
C library uses system provided files like /etc/hosts and /etc/services. \n\
Use this method to get current file path");

static PyObject* dns_getpath(dns_object* self, PyObject* args){
    
    int pathtag = -1;
    char buf[PATH_MAX];
    
    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "i", &pathtag))
        return NULL;

    if(pathtag != IOTHDNS_HOSTS && pathtag != IOTHDNS_SERVICES){
        PyErr_SetString(PyExc_SyntaxError, "invalid pathtag value");
        return NULL;
    }

    if (iothdns_getpath(self->dns, pathtag, buf, PATH_MAX - 1) < 0){
        PyErr_SetFromErrno(PyExc_SyntaxError);
        return NULL;
    }

    return Py_BuildValue("s", &buf);
}

PyDoc_STRVAR(dns_getaddrinfo_doc,"getaddrinfo(node, service, hints)\n\
It returns a tuple (addrinfo_list, code, mem_address), where code is 0 on success,\n\
nonzero values on error. Check getaddrinfo(3) for more details.\n\
'hints' and addrinfo_list are based on struct addrinfo\n\
mem_address is the address in memory of the struct addrinfo. \n\
Call freeaddrinfo using this address to frees the memory");

static PyObject* dns_getaddrinfo(dns_object* self, PyObject* args){
    char* node = NULL;
    char* service = NULL;
    PyObject* hintsObj = NULL;
    struct addrinfo* hints= NULL;
    struct addrinfo* res = NULL;
    int rescode = 0;

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "zzO", &node, &service, &hintsObj))
        return NULL;
    
    if(node == NULL && service == NULL){
        PyErr_SetString(PyExc_SyntaxError, "node or service must not be None");
        return NULL;
    }

    if(hintsObj != Py_None){
        PyObject* tmp = NULL;

        struct addrinfo cur_hints = {
            .ai_flags = ((tmp = PyObject_GetAttrString(hintsObj,"ai_flags")) == NULL ? 0 : *(int*)tmp),
            .ai_family = ((tmp = PyObject_GetAttrString(hintsObj,"ai_family")) == NULL ? 0 : *(int*)tmp),
            .ai_socktype = ((tmp = PyObject_GetAttrString(hintsObj,"ai_socktype")) == NULL ? 0 : *(int*)tmp),
            .ai_protocol = ((tmp = PyObject_GetAttrString(hintsObj,"ai_protocol")) == NULL ? 0 : *(int*)tmp),
            .ai_addrlen = ((tmp = PyObject_GetAttrString(hintsObj,"ai_addrlen")) == NULL ? 0 : *(int*)tmp),
            .ai_addr = (struct sockaddr*) PyObject_GetAttrString(hintsObj,"ai_addr"),
            .ai_canonname = (char*)(PyObject_GetAttrString(hintsObj,"ai_canonname")),
        };

        hints = &cur_hints;
    }
        
    if ((rescode = iothdns_getaddrinfo(self->dns, node, service, hints, &res)) != 0){
        return PyTuple_Pack(3, Py_BuildValue(""), Py_BuildValue("i", rescode), Py_BuildValue(""));
    }

    struct addrinfo* cur = NULL;
    int length = 0;

    for(cur = res; cur != NULL; cur = cur -> ai_next)
        length++;
    
    PyObject* PyRes = PyTuple_New((Py_ssize_t) length);
    Py_ssize_t curPos = 0;

    for(cur = res; cur != NULL; cur = cur -> ai_next){
        PyObject* addressinfo = Py_BuildValue("{s:i, s:i, s:i, s:i, s:i, s:{s:i, s:s}, s:s, s:i}", 
            "ai_flags", cur->ai_flags,
            "ai_family", cur->ai_family,
            "ai_socktype", cur->ai_socktype,
            "ai_protocol", cur->ai_protocol,
            "ai_addrlen", cur->ai_addrlen,
            "ai_addr", 
                "sa_family", cur->ai_addr->sa_family,
                "sa_data", cur->ai_addr->sa_data,
            "ai_canonname", cur->ai_canonname);

        if(PyTuple_SetItem(PyRes, curPos, addressinfo) < 0)
            return NULL;
        curPos++; 
    }
    return PyTuple_Pack(3,PyRes, Py_BuildValue("i", rescode), Py_BuildValue("I", res));
}

PyDoc_STRVAR(dns_freeaddrinfo_doc, "freeaddrinfo(res)\n\
It frees the memory that was allocated for the dinamically\n\
allocated linked list memory");

static PyObject* dns_freeaddrinfo(dns_object* self, PyObject* args){
    int address = 0;

    if(!PyArg_ParseTuple(args, "i", &address))
        return NULL;

    if(address == 0){
        PyErr_SetString(PyExc_SyntaxError, "Invalid input");
        return NULL;
    }

    iothdns_freeaddrinfo((struct addrinfo*)address);

    Py_RETURN_NONE;
}

PyDoc_STRVAR(dns_gai_strerror_doc, "gai_strerror(errcode)\n\
It translates these error codes to a human readable string,\n\
suitable for error reporting.");

static PyObject* dns_gai_strerror(dns_object* self, PyObject* args){
    int code = 0;

    if(!PyArg_ParseTuple(args, "i", &code))
        return NULL;

    if(code == 0){
        PyErr_SetString(PyExc_SyntaxError, "0 means successful operation. No error raised.");
        return NULL;
    }
    
    const char* message = iothdns_gai_strerror(code);

    return PyUnicode_FromString(message);
}

PyDoc_STRVAR(dns_getnameinfo_doc, "getnameinfo(sockaddr, host, service)\n\
It converts a socket address to a corresponding host and service,\n\
in a protocol-independent manner. For more info check getnameinfo(3)\n\
It return a tuple (code, host, service), where code can be converted\n\
to human-readable string husing gai_strerror(3)\n\
If NI_NAMEREQD is set, and hostname cannot be requested, error is raised.");

static PyObject* dns_getnameinfo(dns_object* self, PyObject* args){
    PyObject* sa= NULL;
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int flags = 0;
    int rescode = 0;

    memset(host, 0, sizeof(host));
    memset(serv, 0, sizeof(serv));

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "Ozzi", &sa, &host, &serv, &flags))
        return NULL;
    
    if(host == NULL && serv == NULL){
        PyErr_SetString(PyExc_SyntaxError, "at least one  of  hostname  or service name must be requested");
        return NULL;
    }

    struct sockaddr socketAddress = {
        .sa_family = (*(int *)(PyObject_GetAttrString(sa, "sa_family"))),
        .sa_data = ((char *)(PyObject_GetAttrString(sa, "sa_data"))),
    };

    if((rescode = iothdns_getnameinfo(self->dns, &socketAddress, sizeof(socketAddress), 
            host, NI_MAXHOST, serv, NI_MAXSERV, flags)) != 0){
        return PyTuple_Pack(3, Py_BuildValue("i", rescode), Py_BuildValue(""), Py_BuildValue(""));
    }

    /* NI_NAMEREQD, error if hostname cannot be determinated */
    if(CHECK_BIT(flags, NI_NAMEREQD) && errno != 0){
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return PyTuple_Pack(3, Py_BuildValue("i", rescode), Py_BuildValue("z", host), Py_BuildValue("z", serv));
}

PyDoc_STRVAR(dns_lookup_a_doc,"lookup_a(name, n) \n\
It returns a list of the heading n addresses defined for the queried name.\n\
Address is a dict {s_addr: ..., IP_string: ...} where s_addr is the element of in_addr struct,\n\
IP is the s_addr converted to a string dots-and-number using inet_ntoa(3).\n\
In case name is valid but no IP address is defined, it returns None.\n\
It returns error in case of invalid name.");

static PyObject* dns_lookup_a(dns_object* self, PyObject* args){
    char* name = NULL;
    int n = 0;
    int res;
    char addr_str[INET_ADDRSTRLEN];

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "si", &name, &n))
        return NULL;
    
    struct in_addr in_addrs[n];

    if((res = iothdns_lookup_a(self->dns, name, in_addrs, n)) < 0){
        PyErr_SetString(PyExc_OSError, "non-existent name");
        return NULL;
    }

    /* Valid name, no IP address defined */
    if(res == 0)
        Py_RETURN_NONE;

    PyObject* listAddr = PyList_New((Py_ssize_t) (MIN(res, n)));

    for(int i = 0; i < MIN(res, n); i++){
        PyObject* addr = Py_BuildValue("{s:I,s:s}", "s_addr", in_addrs[i].s_addr,"IP_string", inet_ntop(AF_INET, &in_addrs[i].s_addr, addr_str, INET_ADDRSTRLEN));
        PyList_SET_ITEM(listAddr, i, Py_BuildValue("O", addr));
        if(PyErr_Occurred()){
            Py_DECREF(listAddr);
            return NULL;
        }
    }

    return PyList_Size(listAddr) == 1 ? PyList_GetItem(listAddr, 0) : listAddr;
}


PyDoc_STRVAR(dns_lookup_aaaa_doc,"lookup_aaaa(name, n) \n\
It returns a list of the heading n addresses defined for the queried name.\n\
Address is a dict {s_addr: ..., IP_string: ...} where s_addr is a list of int of s6_addr,\n\
IP is the s_addr converted to a string using inet_ntop(3).\n\
In case name is valid but no IP address is defined, it returns None.\n\
It returns error in case of invalid name.");

static PyObject* dns_lookup_aaaa(dns_object* self, PyObject* args){
    char* name = NULL;
    int n = 0;
    int res;
    char addr6_str[INET6_ADDRSTRLEN];

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "si", &name, &n))
        return NULL;
    
    struct in6_addr in6_addrs[n];

    if((res = iothdns_lookup_aaaa(self->dns, name, in6_addrs, n)) < 0){
        PyErr_SetString(PyExc_OSError, "non-existent name");
        return NULL;
    }

    /* Valid name, no IP address defined */
    if(res == 0)
        Py_RETURN_NONE;

    PyObject* listAddr = PyList_New((Py_ssize_t) (MIN(res, n)));

    for(int i = 0; i < MIN(res, n); i++){
        PyObject* addr6 = PyList_New(16);
        for(int j = 0; j < 16; j++){
            PyList_SET_ITEM(addr6, j, Py_BuildValue("B", in6_addrs[i].s6_addr[j]));
        }

        PyObject* addr = Py_BuildValue("{s:O, s:s}", "s6_addr", addr6, "IP6_string", inet_ntop(AF_INET6, &in6_addrs[i].s6_addr, addr6_str, INET6_ADDRSTRLEN));
        PyList_SET_ITEM(listAddr, i, Py_BuildValue("O", addr));
        if(PyErr_Occurred()){
            Py_DECREF(listAddr);
            return NULL;
        }
    }

    return PyList_Size(listAddr) == 1 ? PyList_GetItem(listAddr, 0) : listAddr;
}

PyDoc_STRVAR(dns_lookup_aaaa_compat_doc,"lookup_aaaa_compat(name, n) \n\
It returns a list of the heading n addresses defined for the queried name.\n\
Address is a dict {IPv6: ..., IP_compat: ...} where IP_compat contain the compat mode\n\
(e.g. ::ffff:1.2.3.4). This value is present only if n > 1.\n\
In case name is valid but no IP address is defined, it returns None.\n\
It returns error in case of invalid name.");

static PyObject* dns_lookup_aaaa_compat(dns_object* self, PyObject* args){
    char* name = NULL;
    int n = 0;
    int res;
    char addr6_str[INET6_ADDRSTRLEN];
    char addr6_compat_str[INET6_ADDRSTRLEN];

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "si", &name, &n))
        return NULL;
    
    struct in6_addr in6_addrs[n];

    if((res = iothdns_lookup_aaaa_compat(self->dns, name, in6_addrs, n)) < 0){
        PyErr_SetString(PyExc_OSError, "non-existent name");
        return NULL;
    }

    /* Valid name, no IP address defined */
    if(res == 0)
        Py_RETURN_NONE;

    PyObject* listAddr = PyList_New(0);
    PyObject* addr = NULL;
    for(int i = 0; i < MIN(res, n); i++){
        char* ipv6addr = inet_ntop(AF_INET6, &in6_addrs[i].s6_addr, addr6_str, INET6_ADDRSTRLEN);
        if(i+1 < MIN(res, n)){
            char* ipv6compat = inet_ntop(AF_INET6, &in6_addrs[++i].s6_addr, addr6_compat_str, INET6_ADDRSTRLEN);
            addr = Py_BuildValue("{s:s, s:s}", "IPv6", ipv6addr ,"IP_compat", ipv6compat);
        }
        else addr = Py_BuildValue("{s:s}", "IPv6", ipv6addr);

        if(PyList_Append(listAddr,addr) < 0)
            return NULL;
    }

    return PyList_Size(listAddr) == 1 ? PyList_GetItem(listAddr, 0) : listAddr;
}

/* need this to pass Py function to C callback function */
static PyObject* Pycb_lookup = NULL;

/* Python function should be defined in the same way */
/*
    Problemi:
    1. Convertire FILE* f della struct iothdns_pkt vpkt in un file io di Python
    2. Union c-like in python?
*/
static int cb_lookup(int section, struct iothdns_rr *rr, struct iothdns_pkt *vpkt, void *arg){
    
    PyObject* args = Py_BuildValue("O", arg);
    PyObject* py_rr = PyDict_New();
    PyObject* py_pkt = PyDict_New();
    PyObject* res = NULL;

    PyDict_SetItemString(py_rr, "name", Py_BuildValue("s", rr->name));
    PyDict_SetItemString(py_rr, "type", Py_BuildValue("I", rr->type));
    PyDict_SetItemString(py_rr, "class", Py_BuildValue("I", rr->class));
    PyDict_SetItemString(py_rr, "ttl", Py_BuildValue("I", rr->ttl));
    PyDict_SetItemString(py_rr, "rdlength", Py_BuildValue("I", rr->rdlength));
    
    PyDict_SetItemString(py_pkt, "flags", Py_BuildValue("i", vpkt->flags));

    /* Build file equivalent in Python */
    int fd;
    int flags;
    char* pyFlag = NULL;
    
    if((fd=fileno(vpkt->f)) < 0){
        return -1;
    }

    flags = fcntl(fd, F_GETFL);
    GET_STRING_FLAG(flags, pyFlag);
    if(pyFlag == NULL){
        PyErr_SetString(PyExc_OSError, "invalid FILE flags");
        return NULL;
    }

    PyObject* file = PyFile_FromFd(fd, vpkt->f->_tmpfname, pyFlag, NULL, NULL, NULL, NULL, NULL);

        // chiedere cvhe tipo di flags sono
    PyDict_SetItemString(py_pkt, "flags", Py_BuildValue("i", vpkt->flags));
    PyDict_SetItemString(py_pkt, "f", file);

    /* concludere parsing */

    if(!PyCallable_Check(Pycb_lookup)){
        PyErr_SetString(PyExc_OSError, "callback must be a function!");
        return NULL;
    }

    (res = PyObject_CallFunctionObjArgs(Pycb_lookup))

    if(!PyNumber_Check(res)){
        PyErr_SetString(PyExc_OSError, "callback should return a number");
        return NULL;
    }

    return *(int*)res;
}

static PyObject* dns_lookup_cb (dns_object* self, PyObject* args){
    /* reset old function */
    Pycb_lookup = NULL;

    char* name = NULL;
    int qtype = -1;
    PyObject* lookup_cb = NULL;
    PyObject* vargs = NULL;

    if(self->dns == NULL){
        PyErr_SetString(PyExc_Exception, "Uninitialized dns");
        return NULL;
    }

    //TODO: check null name
    if(!PyArg_ParseTuple(args, "ziOO", &name, &qtype, &lookup_cb, &vargs))
        return NULL;

    if(!PyCallable_Check(lookup_cb)){
        PyErr_SetString(PyExc_SyntaxError, "invalid function!");
        return NULL;
    }

    Pycb_lookup = lookup_cb_t;

    int res = iothdns_lookup_cb(self->dns,name,qtype,(lookup_cb_t*)cb_lookup, (void*) args)

    Py_RETURN_NONE;
}

static PyMethodDef dns_methods[] = {
    /* configuration */
    {"update", (PyCFunction)dns_update, METH_VARARGS, dns_update_doc},
    {"update_strcfg", (PyCFunction)dns_update_strcfg, METH_VARARGS, dns_update_strcfg_doc},
    {"setpath", (PyCFunction) dns_setpath, METH_VARARGS, dns_setpath_doc},
    {"getpath", (PyCFunction) dns_getpath, METH_VARARGS, dns_getpath_doc},

    /* high level API: client queries */
    {"getaddrinfo", (PyCFunction)dns_getaddrinfo, METH_VARARGS, dns_getaddrinfo_doc},
    {"freeaddrinfo", (PyCFunction)dns_freeaddrinfo, METH_VARARGS, dns_freeaddrinfo_doc},
    {"gai_strerror", (PyCFunction)dns_gai_strerror, METH_VARARGS, dns_gai_strerror_doc},
    {"getnameinfo", (PyCFunction)dns_getnameinfo, METH_VARARGS, dns_getnameinfo_doc},

    /* mid level API: client queries */
    {"lookup_a", (PyCFunction)dns_lookup_a, METH_VARARGS, dns_lookup_a_doc},
    {"lookup_aaaa", (PyCFunction)dns_lookup_aaaa, METH_VARARGS, dns_lookup_aaaa_doc},
    {"lookup_aaaa_compat", (PyCFunction)dns_lookup_aaaa_compat, METH_VARARGS, dns_lookup_aaaa_compat_doc},

    /* low level API: client queries */
    {"lookup_cb", (PyCFunction)dns_lookup_cb, METH_VARARGS, dns_lookup_cb_doc},
    /*
        TODO
    {"lookup_cb_tcp", (PyCFunction)dns_lookup_tcp_cb, METH_VARARGS, dns_lookup_cb_tcp_doc},
    */

    /* low level API: server side */
    /* 
        TODO
    {"udp_process_request", (PyCFunction)dns_udp_process_request, METH_VARARGS, dns_udp_process_request_doc},
    {"tcp_process_request",(PyCFunction)tcp_udp_process_request, METH_VARARGS, tcp_udp_process_request_doc}
    */

    {NULL,NULL} /* sentinel */
};

PyDoc_STRVAR(dns_doc,"DNSBase\n\
This class is used internally as a base type for the DNS class");


PyTypeObject dns_type = {
  PyVarObject_HEAD_INIT(0, 0)                 /* Must fill in type value later */
    "_iothpy.DNSBase",                             /* tp_name */
    sizeof(dns_object),                         /* tp_basicsize */
    0,                                          /* tp_itemsize */
    (destructor)dns_dealloc,                  /* tp_dealloc */
    0,                                          /* tp_vectorcall_offset */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_as_async */
    (reprfunc)dns_repr,                       /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash */
    0,                                          /* tp_call */
    (reprfunc)dns_repr,                        /* tp_str */
    PyObject_GenericGetAttr,                    /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /* tp_flags */
    dns_doc,                                    /* tp_doc */
    0,                                          /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    0,                                          /* tp_iter */
    0,                                          /* tp_iternext */
    dns_methods,                                /* tp_methods */
    0,                                          /* tp_members */
    0,                                          /* tp_getset */
    0,                                          /* tp_base */
    0,                                          /* tp_dict */
    0,                                          /* tp_descr_get */
    0,                                          /* tp_descr_set */
    0,                                          /* tp_dictoffset */
    dns__init__,                                /* tp_init */
    PyType_GenericAlloc,                        /* tp_alloc */
    dns__new__,                                 /* tp_new */
    PyObject_Del,                               /* tp_free */
    0,                                          /* tp_is_gc */
    0,                                          /* tp_bases */
    0,                                          /* tp_mro */
    0,                                          /* tp_cache */
    0,                                          /* tp_subclasses */
    0,                                          /* tp_weaklist */
    0,                                          /* tp_del */
    0,                                          /* tp_version_tag */
    (destructor)dns__del__,                     /* tp_finalize */
};