#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pycoxnet_stack.h"
#include "pycoxnet_socket.h"

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

#include <libioth.h>

PyDoc_STRVAR(pycoxnet_doc,
"_pycoxnet c module\n\
\n\
This module defines the base classes MSocketBase and StackBase\n\
used to interface with the ioth c api. \n\
It also defines the functions needed to offer the same interface as\n\
the built-in socket module\n\
");


#ifdef CMSG_LEN

/* Python interface to CMSG_LEN(length). */

static PyObject *
socket_CMSG_LEN(PyObject *self, PyObject *args)
{
    Py_ssize_t length;
    size_t result;

    if (!PyArg_ParseTuple(args, "n:CMSG_LEN", &length))
        return NULL;
    if (length < 0 || !get_CMSG_LEN(length, &result)) {
        PyErr_Format(PyExc_OverflowError, "CMSG_LEN() argument out of range");
        return NULL;
    }
    return PyLong_FromSize_t(result);
}

PyDoc_STRVAR(CMSG_LEN_doc,
"CMSG_LEN(length) -> control message length\n\
\n\
Return the total length, without trailing padding, of an ancillary\n\
data item with associated data of the given length.  This value can\n\
often be used as the buffer size for recvmsg() to receive a single\n\
item of ancillary data, but RFC 3542 requires portable applications to\n\
use CMSG_SPACE() and thus include space for padding, even when the\n\
item will be the last in the buffer.  Raises OverflowError if length\n\
is outside the permissible range of values.");


#ifdef CMSG_SPACE

/* Python interface to CMSG_SPACE(length). */

static PyObject *
socket_CMSG_SPACE(PyObject *self, PyObject *args)
{
    Py_ssize_t length;
    size_t result;

    if (!PyArg_ParseTuple(args, "n:CMSG_SPACE", &length))
        return NULL;
    if (length < 0 || !get_CMSG_SPACE(length, &result)) {
        PyErr_SetString(PyExc_OverflowError,
                        "CMSG_SPACE() argument out of range");
        return NULL;
    }
    return PyLong_FromSize_t(result);
}

PyDoc_STRVAR(CMSG_SPACE_doc,
"CMSG_SPACE(length) -> buffer size\n\
\n\
Return the buffer size needed for recvmsg() to receive an ancillary\n\
data item with associated data of the given length, along with any\n\
trailing padding.  The buffer space needed to receive multiple items\n\
is the sum of the CMSG_SPACE() values for their associated data\n\
lengths.  Raises OverflowError if length is outside the permissible\n\
range of values.");
#endif    /* CMSG_SPACE */
#endif    /* CMSG_LEN */


/* Python API to getting and setting the default timeout value. */
static PyObject *
socket_getdefaulttimeout(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    if (defaulttimeout < 0) {
        Py_RETURN_NONE;
    }
    else {
        double seconds = _PyTime_AsSecondsDouble(defaulttimeout);
        return PyFloat_FromDouble(seconds);
    }
}

PyDoc_STRVAR(getdefaulttimeout_doc,
"getdefaulttimeout() -> timeout\n\
\n\
Returns the default timeout in seconds (float) for new socket objects.\n\
A value of None indicates that new socket objects have no timeout.\n\
When the socket module is first imported, the default is None.");

static PyObject *
socket_setdefaulttimeout(PyObject *self, PyObject *arg)
{
    _PyTime_t timeout;

    if (socket_parse_timeout(&timeout, arg) < 0)
        return NULL;

    defaulttimeout = timeout;

    Py_RETURN_NONE;
}

PyDoc_STRVAR(setdefaulttimeout_doc,
"setdefaulttimeout(timeout)\n\
\n\
Set the default timeout in seconds (float) for new socket objects.\n\
A value of None indicates that new socket objects have no timeout.\n\
When the socket module is first imported, the default is None.");


static PyMethodDef pycox_methods[] = {
#ifdef CMSG_LEN
    {"CMSG_LEN",   socket_CMSG_LEN, METH_VARARGS, CMSG_LEN_doc},
#ifdef CMSG_SPACE
    {"CMSG_SPACE", socket_CMSG_SPACE, METH_VARARGS, CMSG_SPACE_doc},
#endif
#endif

    {"getdefaulttimeout",  socket_getdefaulttimeout, METH_NOARGS, getdefaulttimeout_doc},
    {"setdefaulttimeout",  socket_setdefaulttimeout, METH_O, setdefaulttimeout_doc},    
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef pycox_module = {
    PyModuleDef_HEAD_INIT,
    "_pycoxnet",   /* name of module */
    pycoxnet_doc,          /* module documentation, may be NULL */
    -1,            /* size of per-interpreter state of the module,
                      or -1 if the module keeps state in global variables. */
    pycox_methods
};

PyMODINIT_FUNC
PyInit__pycoxnet(void)
{
    Py_TYPE(&stack_type) = &PyType_Type;
    Py_TYPE(&socket_type) = &PyType_Type;

    PyObject* module = PyModule_Create(&pycox_module);

    socket_timeout = PyErr_NewException("socket.timeout",
                                        PyExc_OSError, NULL);
    if (socket_timeout == NULL)
        return NULL;
    Py_INCREF(socket_timeout);
    PyModule_AddObject(module, "timeout", socket_timeout);

    /* Add a symbol for the stack type */
    Py_INCREF((PyObject *)&stack_type);
    if(PyModule_AddObject(module, "StackBase", (PyObject*)&stack_type) != 0) {
        return NULL;
    }

    /* Add a symbol for the socket type */
    Py_INCREF((PyObject *)&socket_type);
    if (PyModule_AddObject(module, "MSocketBase",
                           (PyObject *)&socket_type) != 0)
        return NULL;

    return module;
}
