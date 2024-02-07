#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>

typedef struct dns_object{
    PyObject_HEAD
    struct iothdns* dns;
} dns_object;

extern PyTypeObject dns_type;