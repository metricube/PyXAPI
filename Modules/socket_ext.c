/*
 * _socket_ext.c: extension of Python socket module
 * Copyright (C) 2004  Yves Legrandgerard (ylg@pps.jussieu.fr)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*****************************************************************************
 * INCLUDED FILES & MACRO DEFINITIONS
 *****************************************************************************/

#include <Python.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/uio.h>
#include <net/if.h>
#ifndef PyXAPI_H
#include <pyxapi.h>
#endif /* PyXAPI_H */
#include <socketmodule.h>

#define PySocketExt_perror(msg) \
    { \
	PyErr_SetString(PySocketExt_Error, msg); \
	return NULL; \
    }

#undef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#ifdef HAVE_SUNOS
#define _XOPEN_SOURCE 500
#define __EXTENSIONS__
#ifndef CMSG_SPACE
#define CMSG_SPACE(l) ((size_t) _CMSG_HDR_ALIGN(sizeof(struct cmsghdr) + (l)))
#define CMSG_LEN(l) ((size_t) _CMSG_DATA_ALIGN(sizeof(struct cmsghdr)) + (l))
#endif
#endif

typedef struct {
    PyObject_HEAD
    struct cmsghdr *cmsg;
    unsigned char *cmsg_data;
    socklen_t cmsg_datalen;
} PyCMSGObject;

/*****************************************************************************
 * GLOBAL VARIABLES
 *****************************************************************************/

static PyObject *PySocketExt_Error;
static PyTypeObject PyCMSG_Type;

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

static int getsockaddr(unsigned char, PyObject *, struct sockaddr **,
		       socklen_t *);
static PyObject *setsockaddr(struct sockaddr *);

/*****************************************************************************
 * CMSG OBJECT METHODS
 *****************************************************************************/

static PyObject *
PyCMSG_set(PyCMSGObject *self, PyObject *args)
{
    int level, type, datalen;
    unsigned char *p;
    char *data;

    if (!PyArg_ParseTuple(args, "iis#:set", &level, &type, &data, &datalen))
	return NULL;
    if (!datalen)
	PySocketExt_perror("set: data are empty");
    p = PyMem_New(unsigned char, datalen);
    if (p ==  NULL)
	return PyErr_NoMemory();
    memset((void *) p, 0, datalen);
    memset((void *) self->cmsg, 0, sizeof(struct cmsghdr));
    self->cmsg->cmsg_len = CMSG_LEN(datalen);
    self->cmsg->cmsg_level = level;
    self->cmsg->cmsg_type = type;
    PyMem_Free(self->cmsg_data);
    self->cmsg_data = p;
    memcpy((void *) self->cmsg_data, (void *) data, datalen);
    self->cmsg_datalen = datalen;
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(set_doc,
"set(int, int, string) -> None\n\
\n\
Initialize CMSG object:\n\
arg1 -> cmsg_level\n\
arg2 -> cmsg_type\n\
arg3 -> cmsg_data\n\
Return None.");

static PyObject *
PyCMSG_set_from_data(PyCMSGObject *self, PyObject *args)
{
    int datalen;
    unsigned char *data, *p;
    struct cmsghdr *cmsg;
	
    if (!PyArg_ParseTuple(args, "s#", (char *) &cmsg, &datalen))
	return NULL;
    if (datalen != cmsg->cmsg_len)
	PySocketExt_perror(
	    "set_from_data: ancillary data has unexpected size");
    data = CMSG_DATA(cmsg);
    datalen = cmsg->cmsg_len - (data - (unsigned char *) cmsg);
    if (datalen <= 0)
	PySocketExt_perror("set_from_data: can't get data");
    p = PyMem_New(unsigned char, datalen);
    if (p ==  NULL)
	return PyErr_NoMemory();
    memset((void *) p, 0, datalen);
    memset((void *) self->cmsg, 0, sizeof(struct cmsghdr));
    self->cmsg->cmsg_len = cmsg->cmsg_len;
    self->cmsg->cmsg_level = cmsg->cmsg_level;
    self->cmsg->cmsg_type = cmsg->cmsg_type;
    PyMem_Free(self->cmsg_data);
    self->cmsg_data = p;
    memcpy((void *) self->cmsg_data, (void *) data, datalen);
    self->cmsg_datalen = datalen;
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(set_from_data_doc,
"set_from_data(string) -> None\n\
\n\
Initialize CMSG object from raw data (arg1)\n\
Return None.");

static PyObject *
PyCMSG_get(PyCMSGObject *self)
{
    return Py_BuildValue("(iii)s#", self->cmsg->cmsg_len,
			 self->cmsg->cmsg_level, self->cmsg->cmsg_type,
			 (char *) self->cmsg_data, self->cmsg_datalen);
}

PyDoc_STRVAR(get_doc,
"get() -> ((int, int, int), string)\n\
\n\
Return CMSG object as ((cmsg_len, cmsg_level, cmsg_type), cmsg_data");

static PyObject *
PyCMSG_CMSG_DATA(PyCMSGObject *self)
{
    return PyString_FromStringAndSize(
	(char *) self->cmsg_data, self->cmsg_datalen);
}

PyDoc_STRVAR(CMSG_DATA_doc,
"CMSG_DATA() -> string\n\
\n\
Return cmsg_data (equivalent to `cmsg_data' attribute).");

static PyMethodDef PyCMSG_methods[] = {
    {"set", (PyCFunction) PyCMSG_set,
     METH_VARARGS, set_doc},
    {"set_from_data", (PyCFunction) PyCMSG_set_from_data,
     METH_VARARGS, set_from_data_doc},
    {"get", (PyCFunction) PyCMSG_get,
     METH_NOARGS, get_doc},
    {"CMSG_DATA", (PyCFunction) PyCMSG_CMSG_DATA,
     METH_NOARGS, CMSG_DATA_doc},
    {NULL, NULL, 0, NULL}
};

static void
PyCMSG_dealloc(PyCMSGObject *self)
{
    PyMem_Free(self->cmsg);
    PyMem_Free(self->cmsg_data);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyCMSG_getattr(PyCMSGObject *self, char *name)
{
    if (!strcmp(name, "cmsg_len"))
	return Py_BuildValue("i", self->cmsg->cmsg_len);
    if (!strcmp(name, "cmsg_level"))
	return Py_BuildValue("i", self->cmsg->cmsg_level);
    if (!strcmp(name, "cmsg_type"))
	return Py_BuildValue("i", self->cmsg->cmsg_type);
    if (!strcmp(name, "cmsg_data"))
	return PyString_FromStringAndSize(
	    (char *) self->cmsg_data, self->cmsg_datalen);
    if (!strcmp(name, "data")) {
	socklen_t len = CMSG_SPACE(self->cmsg_datalen);
	struct cmsghdr *cmsg;
	PyObject *ret = PyString_FromStringAndSize(NULL, len);

	if (ret == NULL)
	    return NULL;
	memset((void *) PyString_AS_STRING(ret), 0, len);
	cmsg = (struct cmsghdr *) PyString_AS_STRING(ret);
	cmsg->cmsg_len = self->cmsg->cmsg_len;
	cmsg->cmsg_level = self->cmsg->cmsg_level;
	cmsg->cmsg_type = self->cmsg->cmsg_type;
	memcpy((void *) CMSG_DATA(cmsg), (void *) self->cmsg_data,
	       self->cmsg_datalen);
	return ret;
    }
    return Py_FindMethod(PyCMSG_methods, (PyObject *) self, name);
}

static PyObject *
PyCMSG_repr(PyCMSGObject *self)
{
    char buf[512];

    PyOS_snprintf(
	buf, sizeof(buf),
	"<cmsg object, cmsg_len=%d, cmsg_level=%d, cmsg_type=%d, \
cmsg_data: %dbyte(s)>",
	self->cmsg->cmsg_len, self->cmsg->cmsg_level, self->cmsg->cmsg_type,
	self->cmsg_datalen);
    return PyString_FromString(buf);
}

PyDoc_STRVAR(cmsg_object_doc,
"CMSG objects are objects defined to handle ancillary data.\n\
\n\
cmsg() -> CMSG object\n\
\n\
Create a new CMSG object\n\
\n\
Methods of CMSG objects:\n\
\n\
set(int, int, string) -- initialize a CMSG object\n\
set_from_data(string) -- initialize a CMSG object from raw string\n\
get() -- return CMSG object as a tuple\n\
CMSG_DATA() -- return cmsg_data\n\
\n\
Attributes of CMSG objects:\n\
\n\
cmsg_len -- length in bytes, including header\n\
cmsg_level -- originating protocol\n\
cmsg_type -- protocol-specific type\n\
cmsg_data -- data part of ancillary data (as a raw string)\n\
data -- ancillary data as a raw string");

static PyTypeObject PyCMSG_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "socket_ext.cmsg",				/* tp_name */
    sizeof(PyCMSGObject),			/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyCMSG_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyCMSG_getattr,		/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc) PyCMSG_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    0,						/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,				/* tp_flags */
    cmsg_object_doc,				/* tp_doc */
};

/*****************************************************************************
 * MODULE METHODS
 *****************************************************************************/

static PyObject *
PySocketExt_cmsg(PyObject *self)
{
    PyCMSGObject *c;

    c = PyObject_New(PyCMSGObject, &PyCMSG_Type);
    if (c == NULL)
	PySocketExt_perror("cmsg: PyObject_New failed");
    c->cmsg = PyMem_New(struct cmsghdr, 1);
    if (c->cmsg ==  NULL) {
	Py_DECREF(c);
	return PyErr_NoMemory();
    }
    memset((void *) c->cmsg, 0, sizeof(struct cmsghdr));
    c->cmsg_data = NULL;
    c->cmsg_datalen = 0;
    return (PyObject *) c;
}

PyDoc_STRVAR(cmsg_doc,
"cmsg() -> CMSG object\n\
\n\
Create a new CMSG object.");

static PyObject *
PySocketExt_recvmsg(PyObject *self, PyObject *args)
{
    int flags = 0, noc, asize, i, iov_tlen;
    PySocketSockObject *sock;
    PyObject *addr = NULL, *array, *data = NULL, *adata = NULL, *ret = NULL;
    struct iovec *iov;
    struct msghdr msg = {NULL, 0, NULL, 0, NULL, 0, 0};
    struct cmsghdr *cmsg;
#ifdef ENABLE_IPV6
    struct sockaddr_storage sa;
#else
    struct sockaddr_in sa;
#endif

    if (!PyArg_ParseTuple(
	    args, "O!O!|ii:_recvmsg", PySocketModule.Sock_Type,
	    (PyObject *) &sock, &PyTuple_Type, &array, &msg.msg_controllen,
	    &flags))
	return NULL;
    if (msg.msg_controllen > 0) {
	msg.msg_control = PyMem_New(char, msg.msg_controllen);
	if (msg.msg_control == NULL)
	    return PyErr_NoMemory();
	memset((void *) msg.msg_control, 0, msg.msg_controllen);
    }
    asize = PyTuple_GET_SIZE(array);
    if (asize <= 0) {
	PyErr_SetString(
	    PySocketExt_Error, "_recvmsg: scatter/gather array is empty");
	goto fail;
    }
    msg.msg_iov = PyMem_New(struct iovec,  asize);
    if (msg.msg_iov == NULL) {
	PyErr_SetNone(PyExc_MemoryError);
	goto fail;
    }
    memset((void *) msg.msg_iov, 0, asize * sizeof(struct iovec));
    msg.msg_iovlen = asize;
    for (i = 0, iov = msg.msg_iov; i < asize; i++, iov++) {
	PyObject *n = PyTuple_GET_ITEM(array, i);

	if (!PyInt_Check(n) || PyInt_AS_LONG(n) <= 0) {
	    PyErr_SetString(
		PyExc_TypeError,
		"_recvmsg: arg1 must be a tuple of positive integers");
	    goto fail;
	}
	iov->iov_base = (void *) PyMem_New(char, PyInt_AS_LONG(n));
	if (iov->iov_base == NULL) {
	    PyErr_SetNone(PyExc_MemoryError);
	    goto fail;
	}
	iov->iov_len = (size_t) PyInt_AS_LONG(n);
	memset((void *) iov->iov_base, 0, iov->iov_len);
    }
    msg.msg_name = (void *) &sa;
    msg.msg_namelen = sizeof(sa);
    Py_BEGIN_ALLOW_THREADS
    noc = recvmsg(sock->sock_fd, &msg, flags);
    Py_END_ALLOW_THREADS
    if (noc < 0) {
	sock->errorhandler();
	goto fail;
    }
    if ((addr = setsockaddr((struct sockaddr *) msg.msg_name)) == NULL)
	goto fail;
    if ((data = PyTuple_New(asize)) == NULL)
	goto fail;
    for (i = 0, iov_tlen = 0, iov = msg.msg_iov; i < asize; i++, iov++) {
	PyObject *s;

	s = PyString_FromStringAndSize((char *) iov->iov_base,
				       MIN(noc - iov_tlen, iov->iov_len));
	if (s == NULL)
	    goto fail;
	PyTuple_SET_ITEM(data, i, s);
	iov_tlen += iov->iov_len;
	if (noc <= iov_tlen)
	    break;
    }
    if (i + 1 < asize && _PyTuple_Resize(&data, i + 1) < 0)
	goto fail;
    for (cmsg = CMSG_FIRSTHDR(&msg), i = 0; cmsg != NULL;
	 cmsg = CMSG_NXTHDR(&msg, cmsg), i++)
	;
    adata = PyTuple_New(i);
    if (adata == NULL)
	goto fail;
    for (cmsg = CMSG_FIRSTHDR(&msg), i = 0; cmsg != NULL;
	 cmsg = CMSG_NXTHDR(&msg, cmsg), i++) {
	PyCMSGObject *c = (PyCMSGObject *) PySocketExt_cmsg(self);

	if (c == NULL)
	    goto fail;
	if (PyCMSG_set_from_data(
		c, Py_BuildValue("(s#)", (char *) cmsg, cmsg->cmsg_len))
	    == NULL) {
	    Py_DECREF(c);
	    goto fail;
	}
	PyTuple_SET_ITEM(adata, i, (PyObject *) c);
    }
    ret = Py_BuildValue("OOOi", addr, data, adata, msg.msg_flags);
  fail:
    PyMem_Free(msg.msg_control);
    for (iov = msg.msg_iov; iov - msg.msg_iov < msg.msg_iovlen; iov++)
	PyMem_Free(iov->iov_base);
    PyMem_Free(msg.msg_iov);
    Py_XDECREF(addr);
    Py_XDECREF(data);
    Py_XDECREF(adata);
    return ret;
}

PyDoc_STRVAR(recvmsg_doc,
"recvmsg((int, [int, ...]), [int [, int]])\n\
	-> (sockaddr, (string, [string, ...]), ([cmsg, ...]), int)\n\
\n\
First argument is a tuple of integers. Each integer is the size of the\n\
corresponding element of the scatter/gather array. Next (optional)\n\
argument is the length of ancillary data buffer, it's default value\n\
is set to 0. Last (optional) argument is the third argument passed to \n\
recvmsg system call, it's default value is set to 0.\n\
recvmsg returns sender's address info, data received (data are scattered\n\
into a tuple of strings), ancillary data received as a tuple of CMSG objects\n\
and flags on received message. See Unix manual for more details.");

static PyObject *
PySocketExt_sendmsg(PyObject *self, PyObject *args)
{
    int flags = 0, noc, asize, i;
    unsigned char family;
    PySocketSockObject *sock;
    PyObject *addro, *array, *adata = NULL, *ret = NULL;
    struct iovec *iov;
    struct msghdr msg = {NULL, 0, NULL, 0, NULL, 0, 0};

    if (PyArg_ParseTuple(
	    args, "O!BO!O!|Oi:_sendmsg", PySocketModule.Sock_Type,
	    (PyObject *) &sock, &family, &PyTuple_Type, &addro,
	    &PyTuple_Type, &array, &adata, &flags)) {
	if (!getsockaddr(family, addro, (struct sockaddr **) &msg.msg_name,
			 &msg.msg_namelen))
	    return NULL;
    }
    else {
	PyErr_Clear();
	if (!PyArg_ParseTuple(
		args, "O!O!|Oi:_sendmsg", PySocketModule.Sock_Type,
		(PyObject *) &sock, &PyTuple_Type, &array, &adata, &flags))
	    return NULL;
    }
    asize = PyTuple_GET_SIZE(array);
    if (asize <= 0) {
	PyErr_SetString(PySocketExt_Error, "_sendmsg: no data to send");
	goto fail;
    }
    if (adata && adata != Py_None) {
	char *err =
	    "_sendmsg: ancillary data must be a tuple of CMSG objects or None";
	void *p;
	socklen_t clen = 0;

	if (!PyTuple_Check(adata)) {
	    PyErr_SetString(PyExc_TypeError, err);
	    goto fail;
	}
	for (i = 0; i < PyTuple_GET_SIZE(adata); i++) {
	    PyCMSGObject *elt = (PyCMSGObject *) PyTuple_GET_ITEM(adata, i);

	    if (elt->ob_type != &PyCMSG_Type) {
		PyErr_SetString(PyExc_TypeError, err);
		goto fail;
	    }
	    clen += CMSG_SPACE(elt->cmsg_datalen);
	}
	if (clen > 0) {
	    msg.msg_control = (void *) PyMem_New(char, clen);
	    if (msg.msg_control == NULL)
		return PyErr_NoMemory();
	    memset(msg.msg_control, 0, clen);
	    for (i = 0, p = msg.msg_control;
		 i < PyTuple_GET_SIZE(adata); i++) {
		PyCMSGObject *elt =
		    (PyCMSGObject *) PyTuple_GET_ITEM(adata, i);
		socklen_t len = CMSG_SPACE(elt->cmsg_datalen);
		PyObject *data = PyCMSG_getattr(elt, "data");
		
		if (data == NULL) {
		    PyMem_Free(msg.msg_control);
		    goto fail;
		}
		memcpy(p, (void *) PyString_AS_STRING(data), len);
		Py_DECREF(data);
		p = (void *) ((char *) p + len);
	    }
	    msg.msg_controllen = clen;
	}
    }
    msg.msg_iov = PyMem_New(struct iovec, asize);
    if (msg.msg_iov == NULL) {
	PyErr_SetNone(PyExc_MemoryError);
	goto fail;
    }
    memset((void *) msg.msg_iov, 0, asize);
    msg.msg_iovlen = asize;
    for (i = 0, iov = msg.msg_iov; i < asize; i++, iov++) {
	PyObject *s = PyTuple_GET_ITEM(array, i);
	
	if (!PyString_Check(s)) {
	    PyErr_SetString(
		PyExc_TypeError,
		"_sendmsg: data must be a tuple of strings");
	    goto fail;
	}
	iov->iov_base = PyMem_New(char, PyString_Size(s));
	if (iov->iov_base == NULL) {
	    PyErr_SetNone(PyExc_MemoryError);
	    goto fail;
	}
	memset((void *) iov->iov_base, 0, PyString_Size(s));
	memcpy((void *) iov->iov_base, (void *) PyString_AS_STRING(s),
	       PyString_Size(s));
	iov->iov_len = PyString_Size(s);
    }
    Py_BEGIN_ALLOW_THREADS
    noc = sendmsg(sock->sock_fd, &msg, flags);
    Py_END_ALLOW_THREADS
    if (noc < 0) {
	sock->errorhandler();
	goto fail;
    }
    ret = PyInt_FromLong((long) noc);
  fail:
    PyMem_Free(msg.msg_control);
    for (iov = msg.msg_iov; iov - msg.msg_iov < msg.msg_iovlen; iov++)
	PyMem_Free(iov->iov_base);
    PyMem_Free(msg.msg_iov);
    PyMem_Free(msg.msg_name);
    return ret;
};

PyDoc_STRVAR(sendmsg_doc,
"sendmsg([sockaddr,] (string, [string, ...]) [, ([cmsg, ...]) \
| None [, int]])\n\
	-> int\n\
\n\
First (optional) argument is the destination address. Second argument is a\n\
tuple of strings which are the data to be sent. Third (optional) argument\n\
is the ancillary data as a tuple, possibly empty, of CMSG objects. It could\n\
also be None (same as an empty tuple). Last (optional) argument is the third\n\
argument passed to sendmsg system call, it's default value is set to 0.\n\
sendmsg returns the number of bytes sent. See Unix manual for more details.");

static PyObject *
PySocketExt_CMSG_SPACE(PyObject *self, PyObject *args)
{
    unsigned int len;
    
    if (!PyArg_ParseTuple(args, "I", &len))
	return NULL;
    return Py_BuildValue("i", CMSG_SPACE(len));
}

PyDoc_STRVAR(CMSG_SPACE_doc,
"CMSG_SPACE(int) -> int\n\
\n\
Ancillary data object macro. See Unix manual for a description.");

static PyObject *
PySocketExt_CMSG_LEN(PyObject *self, PyObject *args)
{
    unsigned int len;
    
    if (!PyArg_ParseTuple(args, "I", &len))
	return NULL;
    return Py_BuildValue("i", CMSG_LEN(len));
}

PyDoc_STRVAR(CMSG_LEN_doc,
"CMSG_LEN(int) -> int\n\
\n\
Ancillary data object macro. See Unix manual for a description.");

#ifdef HAVE_IF_NAMETOINDEX
static PyObject *
PySocketExt_if_nametoindex(PyObject *self, PyObject *args)
{
    char *ifname;
    
    if (!PyArg_ParseTuple(args, "s", &ifname))
	return NULL;
    return Py_BuildValue("i", if_nametoindex(ifname));
}

PyDoc_STRVAR(if_nametoindex_doc,
"if_nametoindex(string) -> int\n\
\n\
Return the corresponding index of the interface whose name is the name\n\
argument.");
#endif /* HAVE_IF_NAMETOINDEX */

#ifdef HAVE_IF_INDEXTONAME
static PyObject *
PySocketExt_if_indextoname(PyObject *self, PyObject *args)
{
    char ifname[IFNAMSIZ];
    unsigned int index;
    
    if (!PyArg_ParseTuple(args, "I", &index)) {
	return NULL;
    }
    if (if_indextoname(index, ifname) == NULL)
	return PyErr_SetFromErrno(PyExc_RuntimeError);
    return PyString_FromString(ifname);
}

PyDoc_STRVAR(if_indextoname_doc,
"if_indextoname(int) -> string\n\
\n\
Return the corresponding name of the interface whose index is the index\n\
argument.");
#endif /* HAVE_IF_INDEXTONAME */

#if defined(HAVE_IF_NAMEINDEX) && defined(HAVE_IF_FREENAMEINDEX) && \
    defined(HAVE_STRUCT_IF_NAMEINDEX)
static PyObject *
PySocketExt_if_nameindex(PyObject *self)
{
    struct if_nameindex *ifn, *p;
    PyObject *if_index_list;
    
    if ((if_index_list = PyList_New(0)) == NULL)
	return NULL;
    if ((ifn = if_nameindex()) == NULL)
	return PyErr_SetFromErrno(PyExc_RuntimeError);
    for (p = ifn; p->if_index != 0 && p->if_name != NULL; p++) {
	int ret;
	PyObject *pyo;
	
	pyo = Py_BuildValue("is", p->if_index, p->if_name);
	if (pyo == NULL)
	    goto fail;
	ret = PyList_Append(if_index_list, pyo);
	Py_DECREF(pyo);
	if (ret)
	    goto fail;
    }
    if_freenameindex(ifn);
    return if_index_list;
  fail:
    Py_DECREF(if_index_list);
    if_freenameindex(ifn);
    return NULL;
}

PyDoc_STRVAR(if_nameindex_doc,
"if_nameindex() -> [(int, string),...]\n\
\n\
Return the list of all interface names and indexes.");
#endif /* HAVE_IF_NAMEINDEX, ... */

static PyMethodDef PySocketExtMethods[] = {
    {"cmsg", (PyCFunction) PySocketExt_cmsg,
     METH_NOARGS, cmsg_doc},
    {"_recvmsg", (PyCFunction) PySocketExt_recvmsg,
     METH_VARARGS, recvmsg_doc},
    {"_sendmsg", (PyCFunction) PySocketExt_sendmsg,
     METH_VARARGS, sendmsg_doc},
    {"CMSG_SPACE", (PyCFunction) PySocketExt_CMSG_SPACE,
     METH_VARARGS, CMSG_SPACE_doc},
    {"CMSG_LEN", (PyCFunction) PySocketExt_CMSG_LEN,
     METH_VARARGS, CMSG_LEN_doc},
#ifdef HAVE_IF_NAMETOINDEX
    {"if_nametoindex", (PyCFunction) PySocketExt_if_nametoindex,
     METH_VARARGS, if_nametoindex_doc},
#endif /* HAVE_IF_NAMETOINDEX */
#ifdef HAVE_IF_INDEXTONAME
    {"if_indextoname", (PyCFunction) PySocketExt_if_indextoname,
     METH_VARARGS, if_indextoname_doc},
#endif /* HAVE_IF_INDEXTONAME */
#if defined(HAVE_IF_NAMEINDEX) && defined(HAVE_IF_FREENAMEINDEX) && \
    defined(HAVE_STRUCT_IF_NAMEINDEX)
    {"if_nameindex", (PyCFunction) PySocketExt_if_nameindex,
     METH_NOARGS, if_nameindex_doc},
#endif /* HAVE_IF_NAMEINDEX, ... */
    {NULL, NULL, 0, NULL}
};

/*****************************************************************************
 * MODULE INITIALIZATION
 *****************************************************************************/

PyDoc_STRVAR(socket_ext_doc,
"`socket_ext' extends the Python module `socket'.\n\
\n\
- `socket' objects have two new methods: `recvmsg' and `sendmsg'. These\n\
  methods are wrapper for corresponding  UNIX system calls `recvmsg' and\n\
  `sendmsg'.\n\
- it also defines `ancillary data' objects and two functions related to:\n\
  `CMSG_SPACE' and `CMSG_LEN'.\n\
- `socket_ext' module also provides functions to manage interfaces indexes\n\
  defined in RFC3494 and not available from standard Python module `socket'.\n\
  These functions are: `if_nametoindex', `if_indextoname' and `if_nameindex'."
);

PyMODINIT_FUNC
init_socket_ext(void)
{
    PyObject *m, *d;
    PyCMSG_Type.ob_type = &PyType_Type;
    
    m = Py_InitModule3("_socket_ext", PySocketExtMethods, socket_ext_doc);
    d = PyModule_GetDict(m);
    if (PySocketModule_ImportModuleAndAPI())
	return;
    PySocketExt_Error = PyErr_NewException("socket.exterror", NULL, NULL);
    if (PySocketExt_Error == NULL)
	return;
    Py_INCREF(PySocketExt_Error);
    if (PyModule_AddObject(m, "exterror", PySocketExt_Error) != 0)
	return;
    Py_INCREF((PyObject *) &PyCMSG_Type);
    if (PyModule_AddObject(m, "CMSGType", (PyObject *) &PyCMSG_Type) != 0)
	return;
#ifdef MSG_TRUNC
    PyModule_AddIntConstant(m, "MSG_TRUNC", MSG_TRUNC);
#endif
#ifdef MSG_CTRUNC
    PyModule_AddIntConstant(m, "MSG_CTRUNC", MSG_CTRUNC);
#endif
}

/*****************************************************************************
 * LOCAL FUNCTION DEFINITIONS
 *****************************************************************************/

static int
getsockaddr(unsigned char family, PyObject *addro, struct sockaddr **sa,
	    socklen_t *salen)
{
    char *addr;
    unsigned short int port;
    struct addrinfo hints = {AI_NUMERICHOST, family}, *res;
    
    switch(family) {
    case AF_INET:
    {
        struct sockaddr_in *sin;
	
        if (!PyArg_ParseTuple(addro, "si:getsockaddr", &addr, &port))
            return 0;
        if (getaddrinfo(addr, NULL, &hints, &res)) {
	    PyErr_SetString(PySocketExt_Error,
			    "getsockaddr: invalid sockaddr");
	    return 0;
        }
        sin = PyMem_New(struct sockaddr_in, 1);
        if (sin == NULL) {
	    freeaddrinfo(res);
            PyErr_SetNone(PyExc_MemoryError);
            return 0;
        }
        memset((void *) sin, 0, sizeof(*sin));
	memcpy((void *) sin, (void *) res->ai_addr, res->ai_addrlen);
#ifdef HAVE_SOCKADDR_SA_LEN
        sin->sin_len = sizeof(*sin);
#endif
        sin->sin_family = family;
        sin->sin_port = port;
        *sa = (struct sockaddr *) sin;
        *salen = sizeof(*sin);
        break;
    }
#ifdef ENABLE_IPV6
    case AF_INET6:
    {
        struct sockaddr_in6 *sin6;
        unsigned long flowinfo = 0L, scope_id = 0L;
	
        if (!PyArg_ParseTuple(addro, "si|kk:getsockaddr", &addr, &port,
                              &flowinfo, &scope_id))
            return 0;      
	if (getaddrinfo(addr, NULL, &hints, &res)) {
	    PyErr_SetString(PySocketExt_Error,
			    "getsockaddr: invalid sockaddr");
	    return 0;
        }
        sin6 = PyMem_New(struct sockaddr_in6, 1);
        if (sin6 == NULL) {
	    freeaddrinfo(res);
            PyErr_SetNone(PyExc_MemoryError);
            return 0;
        }
        memset((void *) sin6, 0, sizeof(*sin6));
	memcpy((void *) sin6, (void *) res->ai_addr, res->ai_addrlen);
#ifdef HAVE_SOCKADDR_SA_LEN
        sin6->sin6_len = sizeof(*sin6);
#endif
        sin6->sin6_family = family;
        sin6->sin6_port = htons(port);
        sin6->sin6_flowinfo = flowinfo;
        sin6->sin6_scope_id = scope_id;
        *sa = (struct sockaddr *) sin6;
        *salen = sizeof(*sin6);
        break;
    }
#endif
    default:
        PyErr_SetString(PySocketExt_Error, 
                        "getsockaddr: unknown or unsupported address family");
        return 0;
    }
    freeaddrinfo(res);
    return 1;
}

static PyObject *
setsockaddr(struct sockaddr *sa)
{
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    socklen_t salen;
    PyObject *h, *s, *ret = NULL;

    switch(sa->sa_family) {
    case AF_INET:
	salen = sizeof(struct sockaddr_in);
	break;
#ifdef ENABLE_IPV6
    case AF_INET6:
	salen = sizeof(struct sockaddr_in6);
	break;
#endif
    default:
        PySocketExt_perror(
	    "setsockaddr: unknown or unsupported address family");
    }
    if (getnameinfo(sa, salen, host, NI_MAXHOST, serv, NI_MAXSERV,
		    NI_NUMERICHOST | NI_NUMERICSERV))
	PySocketExt_perror("setsockaddr: invalid sockaddr");
    if ((h = PyString_FromString(host)) == NULL)
	return NULL;
    if ((s = PyInt_FromString(serv, NULL, 10)) == NULL)
	return NULL;
    switch(sa->sa_family) {
    case AF_INET:
	ret = Py_BuildValue("OO", h, s);
	break;
#ifdef ENABLE_IPV6
    case AF_INET6:
    {
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;

	ret = Py_BuildValue("OOii", h, s, sin6->sin6_flowinfo,
			    sin6->sin6_scope_id);
	break;
    }
#endif
    }
    Py_DECREF(h);
    Py_DECREF(s);
    return ret;
}
