#include "iothpy_dns.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>

#define IS_PATH(str) (strchr(str, '/') != NULL)

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

    //TODO: cambiare O con O!
    if(!PyArg_ParseTuple(args,"Oz", stackBase, &config))
        return -1;
    
    if(stackBase == NULL){
        PyErr_SetString(PyExc_RuntimeError, "invalid stack");
        return -1;
    }

    stack = (struct ioth*) PyObject_GetAddrString(stackBase, "stack");

    if(config != NULL && !IS_PATH(config)){
        s->dns = iothdns_init_strcfg(stack, config);
    } else {
        /* config NULL or config is Path. iothdns_init handled both. */
        s->dns = iothds_init(stack,config);
    }

    if(s->dns == NULL){
        PyErr_SetFromErrno(PyExc_SyntaxError);
        return -1;
    }

    return 0;
}

static void
dns__del__() dns_object* self{
    //TODO
}


static PyMethodDef dns_methods[] = {
    //TODO
}

PyDoc_STRVAR(dns_doc,
"DNSBase\n\
This class is used internally as a base type for the DNS class"
)


PyTypeObject stack_type = {
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