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