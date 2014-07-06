/*
 * _rfc3542.c: implementation of `Advanced Sockets Application Program
 * Interface (API) for IPv6' (RFC3542)
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
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netdb.h>
#ifndef PyXAPI_H
#include <pyxapi.h>
#endif /*PyXAPI_H*/

#define PyRFC3542_perror(msg) \
    { \
	PyErr_SetString(PyRFC3542_Error, msg); \
	return NULL; \
    }

#ifndef HAVE_UINT8_T
typedef unsigned char uint8_t;
#endif
#ifndef HAVE_UINT32_T
typedef unsigned char uint32_t;
#endif

#ifdef IPV6_RTHDR
#ifndef HAVE_STRUCT_IP6_RTHDR
struct ip6_rthdr {
    uint8_t  ip6r_nxt;        /* next header */
    uint8_t  ip6r_len;        /* length in units of 8 octets */
    uint8_t  ip6r_type;       /* routing type */
    uint8_t  ip6r_segleft;    /* segments left */
    /* followed by routing type specific data */
}
#endif
#ifndef HAVE_STRUCT_IP6_RTHDR0
struct ip6_rthdr0 {
    uint8_t  ip6r0_nxt;       /* next header */
    uint8_t  ip6r0_len;       /* length in units of 8 octets */
    uint8_t  ip6r0_type;      /* always zero */
    uint8_t  ip6r0_segleft;   /* segments left */
    uint32_t ip6r0_reserved;  /* reserved field */
}
#endif

typedef struct {
    PyObject_HEAD
    struct ip6_rthdr **rth;
    void *bp;
    socklen_t bp_len;
} PyINET6_RTHObject;
#endif /* IPV6_RTHDR */

#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
#ifndef HAVE_STRUCT_IP6_OPT
struct ip6_opt {
    uint8_t ip6o_type;
    uint8_t ip6o_len;
};
#endif

typedef struct {
    PyObject_HEAD
    struct ip6_opt **opt;
    void *extbuf;
    socklen_t extlen;
    void *databuf;
} PyINET6_OPTObject;
#endif /* IPV6_HOPOPTS, ... */

#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)   
typedef struct {
    PyObject_HEAD
    struct icmp6_filter *filter;
} PyICMP6_FILTERObject;
#endif /* HAVE_STRUCT_ICMP6_FILTER, ... */

#if defined(HAVE_STRUCT_IN6_PKTINFO) && defined(IPV6_PKTINFO)
typedef struct {
    PyObject_HEAD
    struct in6_pktinfo *pktinfo;
} PyIN6_PKTINFOObject;
#endif /* HAVE_STRUCT_IN6_PKTINFO, ... */

#ifdef IPV6_NEXTHOP
typedef struct {
    PyObject_HEAD
    struct sockaddr_in6 *nexthop;
} PyNEXTHOPObject;
#endif /* IPV6_NEXTHOP */

#if defined(HAVE_STRUCT_IP6_MTUINFO) && defined(IPV6_PATHMTU)
typedef struct {
    PyObject_HEAD
    struct ip6_mtuinfo *mtuinfo;
} PyIP6_MTUINFOObject;
#endif /* HAVE_STRUCT_IP6_MTUINFO, ... */

/*****************************************************************************
 * GLOBAL VARIABLES
 *****************************************************************************/

static PyObject *PyRFC3542_Error;
#ifdef IPV6_RTHDR
static PyTypeObject PyINET6_RTH_Type;
#endif /* IPV6_RTHDR */
#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)
static PyTypeObject PyICMP6_FILTER_Type;
#endif /* HAVE_STRUCT_ICMP6_FILTER, ... */
#if defined(HAVE_STRUCT_IN6_PKTINFO) && defined(IPV6_PKTINFO)
static PyTypeObject PyIN6_PKTINFO_Type;
#endif /* HAVE_STRUCT_IN6_PKTINFO, ... */
#ifdef IPV6_NEXTHOP
static PyTypeObject PyNEXTHOP_Type;
#endif /* IPV6_NEXTHOP */
#if defined(HAVE_STRUCT_IP6_MTUINFO) && defined(IPV6_PATHMTU)
static PyTypeObject  PyIP6_MTUINFO_Type;
#endif /* HAVE_STRUCT_IP6_MTUINFO, ... */

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

#ifdef IPV6_RTHDR
#ifndef HAVE_INET6_RTH_SPACE
static socklen_t inet6_rth_space(int, int);
#endif
#ifndef HAVE_INET6_RTH_INIT
static void *inet6_rth_init(void *, socklen_t, int, int);
#endif
#ifndef HAVE_INET6_RTH_ADD
static int inet6_rth_add(void *, const struct in6_addr *);
#endif
#ifndef HAVE_INET6_RTH_SEGMENTS
static int inet6_rth_segments(const void *);
#endif
#ifndef HAVE_INET6_RTH_REVERSE
static int inet6_rth_reverse(const void *, void *);
#endif
#ifndef HAVE_INET6_RTH_GETADDR
static struct in6_addr *inet6_rth_getaddr(const void *, int);
#endif
#endif /* IPV6_RTHDR */
#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
#ifndef HAVE_INET6_OPT_INIT
static int inet6_opt_init(void *, socklen_t);
#endif
#ifndef HAVE_INET6_OPT_APPEND
static int inet6_opt_append(void *, socklen_t, int, uint8_t, socklen_t,
			    uint8_t, void **);
#endif
#ifndef HAVE_INET6_OPT_FINISH
static int inet6_opt_finish(void *, socklen_t, int);
#endif
#ifndef HAVE_INET6_OPT_SET_VAL
static int inet6_opt_set_val(void *, int, void *, socklen_t);
#endif
#ifndef HAVE_INET6_OPT_NEXT
static int inet6_opt_next(void *, socklen_t, int, uint8_t *, socklen_t *,
			  void **);
#endif
#ifndef HAVE_INET6_OPT_FIND
static int inet6_opt_find(void *, socklen_t, int, uint8_t, socklen_t *,
			  void **);
#endif
#ifndef HAVE_INET6_OPT_GET_VAL
static int inet6_opt_get_val(void *, int, void *, socklen_t);
#endif
#endif /* IPV6_HOPOPTS, ... */

/*****************************************************************************
 * INET6_RTH OBJECT METHODS
 *****************************************************************************/

#ifdef IPV6_RTHDR
static PyObject *
PyINET6_RTH_set(PyINET6_RTHObject *self, PyObject *args)
{
    int type, segleft, segments, argc = PyTuple_GET_SIZE(args);

    if (argc < 2)
	return PyErr_Format(
	    PyExc_TypeError,
	    "set() takes at least 2 arguments (%d given)", argc);
    if (!PyArg_ParseTuple(PyTuple_GetSlice(args, 0, 1), "i:set", &type))
	return NULL;
    if (PyArg_ParseTuple(PyTuple_GetSlice(args, 1, 2), "i", &segments))
	segleft = argc - 2;
    else {
	PyErr_Clear();
	segments = segleft = argc - 1;
    }
    if (segments < segleft)
	PyRFC3542_perror("set: routing header size is too small");
    switch (type) {
    case IPV6_RTHDR_TYPE_0:
    {
	int i, bp_len;
	void *bp;
	PyObject *op;

	bp_len = inet6_rth_space(type, segments);
	if (bp_len == 0)
	    PyRFC3542_perror(
		"set: inet6_rth_space: invalid type or segment number");
	bp = (void *) PyMem_New(unsigned char, bp_len);
	if (bp == NULL)
	    return PyErr_NoMemory();
	if (inet6_rth_init(bp, bp_len, type, segments) ==  NULL) {
	    PyMem_Free(bp);
	    PyRFC3542_perror("set: inet6_rth_init failed");
	}
	op = PyTuple_GetSlice(args, argc - segleft, argc);
	for (i = 0; i < segleft; i++) {
	    int ret;
	    struct addrinfo hints = {AI_NUMERICHOST, AF_INET6}, *res;
	    PyObject *elt = PyTuple_GET_ITEM(op, i);
	    
	    if (!PyString_Check(elt)) {
		PyErr_SetString(
		    PyRFC3542_Error, "set: invalid hostname or IPv6 address");
		goto fail;
	    }
	    if (getaddrinfo(PyString_AS_STRING(elt), NULL, &hints, &res)) {
		hints.ai_flags = 0;
		if (getaddrinfo(PyString_AS_STRING(elt), NULL, &hints, &res)) {
		    PyErr_SetString(
			PyRFC3542_Error,
			"set: invalid hostname or IPv6 address");
		    goto fail;
		}
	    }
	    ret = inet6_rth_add(
		bp, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr);
	    freeaddrinfo(res);
	    if (ret == -1) {
		PyErr_SetString(PyRFC3542_Error, "set: inet6_rth_add failed");
		goto fail;
	    }
	}
	PyMem_Free(self->bp);
	self->bp = bp;
	self->bp_len = bp_len;
	Py_DECREF(op);
	Py_INCREF(Py_None);
	return Py_None;
      fail:
	PyMem_Free(bp);
	Py_DECREF(op);
	return NULL;
    }
    default:
	PyRFC3542_perror("set: invalid routing header type");
    }
}

PyDoc_STRVAR(inet6_rth_set_doc,
"set(int, int) -> None\n\
or\n\
set(int, [int,] string [string, ...]) -> None\n\
\n\
set(int, int) is equivalent to inet6_rth_init(int, int) and\n\
set(int, [int,] string [string, ...]) is equivalent to\n\
inet6_rth_init(int, [int]) followed by inet6_rth_add(self, string)\n\
[inet6_rth_add(self, string) ...].\n\
Return None.");
 
static PyObject *
PyINET6_RTH_set_from_data(PyINET6_RTHObject *self, PyObject *args)
{
    char *data;
    int datalen;
    void *bp;
    struct ip6_rthdr *rth;

    if (!PyArg_ParseTuple(args, "s#:set_from_data", &data, &datalen))
	return NULL;
    if (datalen < sizeof(struct ip6_rthdr))
	PyRFC3542_perror("set_from_data: routing header is truncated");
    rth = (struct ip6_rthdr *) data;
    switch (rth->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
    {
	struct ip6_rthdr0 *rth0 = (struct ip6_rthdr0 *) rth;

	if (rth0->ip6r0_len % 2)
	    PyRFC3542_perror(
		"set_from_data: routing header: length field must be even");
	if (rth0->ip6r0_len >> 1 < rth0->ip6r0_segleft)
	    PyRFC3542_perror(
		"set_from_data: routing header is inconsistent");
	if (datalen != (rth0->ip6r0_len << 3) + 8)
	    PyRFC3542_perror("set_from_data: routing header has bad length");
	bp = (void *) PyMem_New(unsigned char, datalen);
	if (bp == NULL)
	    return PyErr_NoMemory();
	memset(bp, 0, datalen);
	memcpy(bp, (void *) data, datalen);
	PyMem_Free(self->bp);
	self->bp = bp;
	self->bp_len = datalen;
	break;
    }
    default:
	PyRFC3542_perror("set_from_data: invalid routing header type");
    }
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(inet6_rth_set_from_data_doc,
"set_from_data(string) -> None\n\
\n\
Initialize INET6_RTH object from raw data (arg1)\n\
Return None.");

static PyObject *
PyINET6_RTH_get(PyINET6_RTHObject *self)
{
    if (*self->rth == NULL) {
	Py_INCREF(Py_None);
	return Py_None;
    }
    switch ((*self->rth)->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
    {
	struct ip6_rthdr0 *rth0 = (struct ip6_rthdr0 *) *self->rth;
	int i, segments = rth0->ip6r0_len >> 1;
	PyObject *op = PyTuple_New(segments + 1);

	if (op == NULL)
	    return NULL;
	PyTuple_SET_ITEM(op, 0, Py_BuildValue("iiiii",
					      rth0->ip6r0_nxt,
					      rth0->ip6r0_len,
					      rth0->ip6r0_type,
					      rth0->ip6r0_segleft,
					      rth0->ip6r0_reserved));
	for (i = 0; i < segments; i++) {
	    char host[NI_MAXHOST];
	    struct sockaddr_in6 sin6 = {
#ifdef HAVE_SOCKADDR_SA_LEN
		sizeof(sin6),
#endif
		AF_INET6,
		0,
		0
	    };
	    memcpy((void *) &sin6.sin6_addr,
		   (void *) ((struct in6_addr *) ((char *) self->bp + 8) + i),
		   sizeof(struct in6_addr));
	    sin6.sin6_scope_id = 0;
	    if (getnameinfo((struct sockaddr *) &sin6, sizeof(sin6),
			    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) {
		Py_DECREF(op);
		return NULL;
	    }
	    PyTuple_SET_ITEM(op, i + 1, Py_BuildValue("s", host));
	}
	return op;
    }
    default:
	return Py_BuildValue("iiii",
			     (*self->rth)->ip6r_nxt,
			     (*self->rth)->ip6r_len,
			     (*self->rth)->ip6r_type,
			     (*self->rth)->ip6r_segleft);
    }
}

PyDoc_STRVAR(inet6_rth_get_doc,
"get() -> ((int, int, int, int[, int]), [string, ...])\n\
\n\
Return INET6_RTH object as ((ip6r_nxt, ip6r_len, ip6r_type, ip6r_segleft,\n\
[ip6r0_reserved])[, addr[, addr ...]]). See structure `ip6_rthdr' and\n\
structure `ip6_rthdr0' in RFC3542.");

static PyMethodDef PyINET6_RTH_methods[] = {
    {"set", (PyCFunction) PyINET6_RTH_set,
     METH_VARARGS, inet6_rth_set_doc},
    {"set_from_data", (PyCFunction) PyINET6_RTH_set_from_data,
     METH_VARARGS, inet6_rth_set_from_data_doc},
    {"get", (PyCFunction) PyINET6_RTH_get,
     METH_NOARGS, inet6_rth_get_doc},
    {NULL, NULL, 0, NULL}
};

static void
PyINET6_RTH_dealloc(PyINET6_RTHObject *self)
{
    PyMem_Free(self->bp);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyINET6_RTH_getattr(PyINET6_RTHObject *self, char *name)
{
    if (!strcmp(name, "data"))
	return PyString_FromStringAndSize((char *) self->bp, self->bp_len);
    return Py_FindMethod(PyINET6_RTH_methods, (PyObject *) self, name);
}

PyDoc_STRVAR(inet6_rth_object_doc,
"INET6_RTH objects are defined to handle routing headers\n\
\n\
inet6_rth() -> INET6_RTH object\n\
\n\
Create a new INET6_RTH object\n\
\n\
Methods of INET6_RTH objects:\n\
\n\
set(int, int) or\n\
set(int, [int,] string [string, ...]) -- init a routing header\n\
  or init a routing header and add segments to it. Equivalent to\n\
  inet6_rth_init() followed by one or more inet6_rth_add()\n\
set_from_data(string) -- init a routing header from raw data\n\
get() -- return a routing header as a tuple: first item is the\n\
  routing header as a tuple of its fields, remaining arguments\n\
  are segments as textual IPv6 addresses\n\
\n\
Attributes of INET6_RTH objects:\n\
\n\
data -- INET6_RTH object as a raw string");

static PyTypeObject PyINET6_RTH_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "rfc3542.inet6_rth",			/* tp_name */
    sizeof(PyINET6_RTHObject),			/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyINET6_RTH_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyINET6_RTH_getattr,		/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
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
    inet6_rth_object_doc,			/* tp_doc */
};
#endif /* IPV6_RTHDR */

/*****************************************************************************
 * INET6_OPT OBJECT METHODS
 *****************************************************************************/

#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
static PyObject *
PyINET6_OPT_set(PyINET6_OPTObject *self, PyObject *args)
{
    int extlen;
    void *extbuf;

    if (!PyArg_ParseTuple(args, "i:set", &extlen))
	return NULL;
    if (extlen < 2)
	PyRFC3542_perror("set: argument must be an integer >= 2");
    extbuf = (void *) PyMem_New(unsigned char, extlen);
    if (extbuf == NULL)
	return PyErr_NoMemory();
    memset(extbuf, 0, extlen);
    PyMem_Free(self->extbuf);
    self->extbuf = extbuf;
    self->extlen = extlen;
    self->databuf = NULL;
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(inet6_opt_set_doc,
"set(int) -> None\n\
\n\
Initialize an extension header. arg1 must be an integer >= 2. See also\n\
inet6_opt_init(). Return None.");

static PyObject *
PyINET6_OPT_set_from_data(PyINET6_OPTObject *self, PyObject *args)
{
    char *data;
    int datalen;
    void *extbuf;

    if (!PyArg_ParseTuple(args, "s#:set_from_data", &data, &datalen))
	return NULL;
    if (datalen <= 0 || datalen % 8)
	PyRFC3542_perror("set_from_data: data length must be a multiple of 8");
    extbuf = (void *) PyMem_New(unsigned char, datalen);
    if (extbuf == NULL)
	return PyErr_NoMemory();
    memset(extbuf, 0, datalen);
    memcpy(extbuf, (void *) data, datalen);
    PyMem_Free(self->extbuf);
    self->extbuf = extbuf;
    self->extlen = datalen;
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(inet6_opt_set_from_data_doc,
"set_from_data(string) -> None\n\
\n\
Initialize INET6_OPT object from raw data (arg1)\n\
Return None.");

static PyObject *
PyINET6_OPT_get(PyINET6_OPTObject *self)
{
    if (self->extbuf == NULL) {
	Py_INCREF(Py_None);
	return Py_None;
    }
    return Py_BuildValue(
	"ii", (*self->opt)->ip6o_type, (*self->opt)->ip6o_len);
}

PyDoc_STRVAR(inet6_opt_get_doc,
"get() -> None\n\
\n\
Return INET6_OPT object as (ip6o_type, ip6o_len). See structure `ip6_opt'\n\
in RFC3542.");

static PyMethodDef PyINET6_OPT_methods[] = {
    {"set", (PyCFunction) PyINET6_OPT_set,
     METH_VARARGS, inet6_opt_set_doc},
    {"set_from_data", (PyCFunction) PyINET6_OPT_set_from_data,
     METH_VARARGS, inet6_opt_set_from_data_doc},
    {"get", (PyCFunction) PyINET6_OPT_get,
     METH_NOARGS, inet6_opt_get_doc},
    {NULL, NULL, 0, NULL}
};

static void
PyINET6_OPT_dealloc(PyINET6_OPTObject *self)
{
    PyMem_Free(self->extbuf);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyINET6_OPT_getattr(PyINET6_OPTObject *self, char *name)
{
    if (!strcmp(name, "data"))
	return PyString_FromStringAndSize((char *) self->extbuf, self->extlen);
    return Py_FindMethod(PyINET6_OPT_methods, (PyObject *) self, name);
}

PyDoc_STRVAR(inet6_opt_object_doc,
"INET6_OPT objects are defined to handle extension headers\n\
\n\
inet6_opt() -> INET6_OPT object\n\
\n\
Create a new INET6_OPT object\n\
\n\
Methods of INET6_OPT objects:\n\
\n\
set(int) -- initialize an extension header\n\
set_from_data(string) -- initialize an extension header from raw data\n\
get() -- return a extension header as a 2-tuple: (type/nxt, len)\n\
\n\
Attributes of INET6_OPT objects:\n\
\n\
data -- INET6_OPT object as a raw string");

static PyTypeObject PyINET6_OPT_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "rfc3542.inet6_opt",			/* tp_name */
    sizeof(PyINET6_OPTObject),			/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyINET6_OPT_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyINET6_OPT_getattr,		/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
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
    inet6_opt_object_doc,			/* tp_doc */
};
#endif /* IPV6_HOPOPTS, ... */

/*****************************************************************************
 * ICMP6_FILTER OBJECT METHODS
 *****************************************************************************/

#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)
#ifdef ICMP6_FILTER_SETBLOCK
static PyObject *
PyICMP6_FILTER_SETBLOCK(PyICMP6_FILTERObject *self, PyObject *args)
{
    unsigned char type;

    if (!PyArg_ParseTuple(args, "B:ICMP6_FILTER_SETBLOCK", &type))
	return NULL;
    ICMP6_FILTER_SETBLOCK(type, self->filter);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(ICMP6_FILTER_SETBLOCK_doc,
"ICMP6_FILTER_SETBLOCK(int) -> None\n\
\n\
ICMPv6 messages of type arg1 are passed to the application. Return None.");
#endif

#ifdef ICMP6_FILTER_SETPASS
static PyObject *
PyICMP6_FILTER_SETPASS(PyICMP6_FILTERObject *self, PyObject *args)
{
    unsigned char type;

    if (!PyArg_ParseTuple(args, "B:ICMP6_FILTER_SETPASS", &type))
	return NULL;
    ICMP6_FILTER_SETPASS(type, self->filter);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(ICMP6_FILTER_SETPASS_doc,
"ICMP6_FILTER_SETPASS(int) -> None\n\
\n\
ICMPv6 messages of type arg1 are blocked from being passed to the\n\
application. Return None.");
#endif

#ifdef ICMP6_FILTER_SETBLOCKALL
static PyObject *
PyICMP6_FILTER_SETBLOCKALL(PyICMP6_FILTERObject *self)
{
    ICMP6_FILTER_SETBLOCKALL(self->filter);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(ICMP6_FILTER_SETBLOCKALL_doc,
"ICMP6_FILTER_SETBLOCKALL() -> None\n\
\n\
All ICMPv6 messages are blocked from being passed to the application.\n\
Return None.");
#endif

#ifdef ICMP6_FILTER_SETPASSALL
static PyObject *
PyICMP6_FILTER_SETPASSALL(PyICMP6_FILTERObject *self)
{
    ICMP6_FILTER_SETPASSALL(self->filter);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(ICMP6_FILTER_SETPASSALL_doc,
"ICMP6_FILTER_SETPASSALL() -> None\n\
\n\
All ICMPv6 messages are blocked from being passed to the application.\n\
Return None.");
#endif

#ifdef ICMP6_FILTER_WILLBLOCK
static PyObject *
PyICMP6_FILTER_WILLBLOCK(PyICMP6_FILTERObject *self, PyObject *args)
{
    unsigned char type;

    if (!PyArg_ParseTuple(args, "B:ICMP6_FILTER_WILLBLOCK", &type))
	return NULL;
    return Py_BuildValue("i", ICMP6_FILTER_WILLBLOCK(type, self->filter));
}

PyDoc_STRVAR(ICMP6_FILTER_WILLBLOCK_doc,
"ICMP6_FILTER_WILLBLOCK(int) -> int\n\
\n\
Return 1 or 0 depending whether ICMPv6 messages of type arg1 are blocked\n\
from being passed to the application");
#endif

#ifdef ICMP6_FILTER_WILLPASS
static PyObject *
PyICMP6_FILTER_WILLPASS(PyICMP6_FILTERObject *self, PyObject *args)
{
    unsigned char type;

    if (!PyArg_ParseTuple(args, "B:ICMP6_FILTER_WILLPASS", &type))
	return NULL;
    return Py_BuildValue("i", ICMP6_FILTER_WILLPASS(type, self->filter));
}

PyDoc_STRVAR(ICMP6_FILTER_WILLPASS_doc,
"ICMP6_FILTER_WILLPASS(int) -> int\n\
\n\
Return 1 or 0 depending whether ICMPv6 messages of this type are passed to\n\
the application");
#endif

static PyMethodDef PyICMP6_FILTER_methods[] = {
#ifdef ICMP6_FILTER_SETBLOCK
    {"ICMP6_FILTER_SETBLOCK", (PyCFunction) PyICMP6_FILTER_SETBLOCK,
     METH_VARARGS, ICMP6_FILTER_SETBLOCK_doc},
#endif
#ifdef ICMP6_FILTER_SETPASS
    {"ICMP6_FILTER_SETPASS", (PyCFunction) PyICMP6_FILTER_SETPASS,
     METH_VARARGS, ICMP6_FILTER_SETPASS_doc},
#endif
#ifdef ICMP6_FILTER_SETBLOCKALL
    {"ICMP6_FILTER_SETBLOCKALL", (PyCFunction) PyICMP6_FILTER_SETBLOCKALL,
     METH_NOARGS, ICMP6_FILTER_SETBLOCKALL_doc},
#endif
#ifdef ICMP6_FILTER_SETPASSALL
    {"ICMP6_FILTER_SETPASSALL", (PyCFunction) PyICMP6_FILTER_SETPASSALL,
     METH_NOARGS, ICMP6_FILTER_SETPASSALL_doc},
#endif
#ifdef ICMP6_FILTER_WILLBLOCK
    {"ICMP6_FILTER_WILLBLOCK", (PyCFunction) PyICMP6_FILTER_WILLBLOCK,
     METH_VARARGS, ICMP6_FILTER_WILLBLOCK_doc},
#endif
#ifdef ICMP6_FILTER_WILLPASS
    {"ICMP6_FILTER_WILLPASS", (PyCFunction) PyICMP6_FILTER_WILLPASS,
     METH_VARARGS, ICMP6_FILTER_WILLPASS_doc},
#endif
    {NULL, NULL, 0, NULL}
};

static void
PyICMP6_FILTER_dealloc(PyICMP6_FILTERObject *self)
{
    PyMem_Free(self->filter);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyICMP6_FILTER_getattr(PyICMP6_FILTERObject *self, char *name)
{
    if (!strcmp(name, "data"))
	return PyString_FromStringAndSize(
	    (char *) self->filter, sizeof(struct icmp6_filter));
    return Py_FindMethod(PyICMP6_FILTER_methods, (PyObject *) self, name);
}

PyDoc_STRVAR(icmp6_filter_object_doc,
"ICMP6_FILTER objects are defined to handle ICMPv6 filters\n\
\n\
icmp6filter() -> ICMP6_FILTER object\n\
\n\
Create a new ICMP6_FILTER object\n\
\n\
Methods of ICMP6_FILTER objects:\n\
\n\
ICMP6_FILTER_SETBLOCK(type) -- ICMPv6 messages of this type\n\
  are passed to the application\n\
ICMP6_FILTER_SETPASS(type) -- ICMPv6 messages of this type\n\
  are blocked from being passed to the application\n\
ICMP6_FILTER_SETBLOCKALL() -- all ICMPv6 messages are blocked\n\
  from being passed to the application\n\
ICMP6_FILTER_SETPASSALL() -- all ICMPv6 messages are passed\n\
  to the application\n\
ICMP6_FILTER_WILLBLOCK(type) -- return 1 or 0 depending whether\n\
  ICMPv6 messages of this type are blocked from being passed\n\
  to the application\n\
ICMP6_FILTER_WILLPASS(type) -- return 1 or 0 depending whether\n\
  ICMPv6 messages of this type are passed to the application\n\
\n\
Attributes of ICMP6_FILTER objects:\n\
\n\
data -- ICMP6_FILTER object as a raw string");

static PyTypeObject PyICMP6_FILTER_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "rfc3542.icmp6_filter",			/* tp_name */
    sizeof(PyICMP6_FILTERObject),		/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyICMP6_FILTER_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyICMP6_FILTER_getattr,	/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
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
    icmp6_filter_object_doc,			/* tp_doc */
};
#endif /* HAVE_STRUCT_ICMP6_FILTER, ... */

/*****************************************************************************
 * IN6_PKTINFO OBJECT METHODS
 *****************************************************************************/

#if defined(HAVE_STRUCT_IN6_PKTINFO) && defined(IPV6_PKTINFO)
static PyObject *
PyIN6_PKTINFO_set(PyIN6_PKTINFOObject *self, PyObject *args)
{
    unsigned int ifindex;
    char *addr;
    struct addrinfo hints = {AI_NUMERICHOST, AF_INET6}, *res;

    if (!PyArg_ParseTuple(args, "sI:set", &addr, &ifindex))
	return NULL;
    if (getaddrinfo(addr, NULL, &hints, &res)) {
	hints.ai_flags = 0;
	if (getaddrinfo(addr, NULL, &hints, &res))
	    PyRFC3542_perror("set: invalid hostname or IPv6 address");
    }
    memset((void *) self->pktinfo, 0, sizeof(struct in6_pktinfo));
    memcpy((void *) &self->pktinfo->ipi6_addr,
	   (void *) &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
	   sizeof(struct in6_addr));
    self->pktinfo->ipi6_ifindex = ifindex;
    freeaddrinfo(res);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(in6_pktinfo_set_doc,
"set(string, int) -> None\n\
\n\
Initialize a IN6_PKTINFO object. Arg1 is src/dst IPv6 address, arg2\n\
is send/recv interface index. Return None.");

static PyObject *
PyIN6_PKTINFO_set_from_data(PyIN6_PKTINFOObject *self, PyObject *args)
{
    char *data;
    int datalen;

    if (!PyArg_ParseTuple(args, "s#:set_from_data", &data, &datalen))
	return NULL;
    if (datalen != sizeof(struct in6_pktinfo))
	PyRFC3542_perror("set_from_data: data has bad length");
    memset((void *) self->pktinfo, 0, sizeof(struct in6_pktinfo));
    memcpy((void *) self->pktinfo, (void *) data, datalen);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(in6_pktinfo_set_from_data_doc,
"set_from_data(string) -> None\n\
\n\
Initialize IN6_PKTINFO object from raw data (arg1)\n\
Return None.");

static PyObject *
PyIN6_PKTINFO_get(PyIN6_PKTINFOObject *self)
{
    char host[NI_MAXHOST];
    struct sockaddr_in6 sin6;

    memset((void *) &sin6, 0, sizeof(sin6));
#ifdef HAVE_SOCKADDR_SA_LEN
    sin6.sin6_len = sizeof(sin6);
#endif
    sin6.sin6_family = AF_INET6;
    memcpy((void *) &sin6.sin6_addr, (void *) &self->pktinfo->ipi6_addr,
	   sizeof(struct in6_addr));
    if (getnameinfo((struct sockaddr *) &sin6, sizeof(sin6), host, NI_MAXHOST,
		    NULL, 0, NI_NUMERICHOST))
	PyRFC3542_perror("get: invalid IPv6 address in pktinfo");
    return Py_BuildValue("si", host, self->pktinfo->ipi6_ifindex);
}

PyDoc_STRVAR(in6_pktinfo_get_doc,
"get() -> (string, int)\n\
\n\
Return (`src/dst IPv6 address', `send/recv interface index').");

static PyMethodDef PyIN6_PKTINFO_methods[] = {
    {"set", (PyCFunction) PyIN6_PKTINFO_set,
     METH_VARARGS, in6_pktinfo_set_doc},
    {"set_from_data", (PyCFunction) PyIN6_PKTINFO_set_from_data,
     METH_VARARGS, in6_pktinfo_set_from_data_doc},
    {"get", (PyCFunction) PyIN6_PKTINFO_get,
     METH_NOARGS, in6_pktinfo_get_doc},
    {NULL, NULL, 0, NULL}
};

static void
PyIN6_PKTINFO_dealloc(PyIN6_PKTINFOObject *self)
{
    PyMem_Free(self->pktinfo);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyIN6_PKTINFO_getattr(PyIN6_PKTINFOObject *self, char *name)
{
    if (!strcmp(name, "data"))
	return PyString_FromStringAndSize(
	    (char *) self->pktinfo, sizeof(struct in6_pktinfo));
    if (!strcmp(name, "size"))
	return Py_BuildValue("i", sizeof(struct in6_pktinfo));
    return Py_FindMethod(PyIN6_PKTINFO_methods, (PyObject *) self, name);
}

static PyObject *
PyIN6_PKTINFO_repr(PyIN6_PKTINFOObject *self)
{
    PyObject *p = PyIN6_PKTINFO_get(self);
    char *addr, buf[512];
    unsigned long ifindex;

    if (p == NULL)
	return NULL;
    addr = PyString_AS_STRING(PyTuple_GET_ITEM(p, 0));
    ifindex = PyInt_AsUnsignedLongMask(PyTuple_GET_ITEM(p, 1));
    PyOS_snprintf(
	buf, sizeof(buf), "<in6_pktinfo object, addr='%s', ifindex=%lu>",
	addr, ifindex);
    Py_DECREF(p);
    return PyString_FromString(buf);
}

PyDoc_STRVAR(in6_pktinfo_object_doc,
"IN6_PKTINFO objects are defined to handle packet information option\n\
\n\
in6_pktinfo() -> IN6_PKTINFO object\n\
\n\
Create a new IN6_PKTINFO object\n\
\n\
Methods of IN6_PKTINFO objects:\n\
\n\
set(string, int) -- initialize a packet information\n\
set_from_data(string) -- initialize a packet information from raw data\n\
get() -- return a packet information as a 2-tuple (`src/dst IPv6 address',\n\
  `send/recv interface index')\n\
\n\
Attributes of IN6_PKTINFO objects:\n\
\n\
data -- IN6_PKTINFO object as a raw string\n\
size -- size in bytes of `in6_pktinfo' option (not IN6_PKTINFO object)");

static PyTypeObject PyIN6_PKTINFO_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "rfc3542.in6_pktinfo",			/* tp_name */
    sizeof(PyIN6_PKTINFOObject),		/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyIN6_PKTINFO_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyIN6_PKTINFO_getattr,	/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc) PyIN6_PKTINFO_repr,		/* tp_repr */
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
    in6_pktinfo_object_doc,			/* tp_doc */
};
#endif /* HAVE_STRUCT_IN6_PKTINFO, ... */

/*****************************************************************************
 * NEXTHOP OBJECT METHODS
 *****************************************************************************/

#ifdef IPV6_NEXTHOP
static PyObject *
PyNEXTHOP_set(PyNEXTHOPObject *self, PyObject *args)
{
    char *addr;
    struct addrinfo hints = {AI_NUMERICHOST, AF_INET6}, *res;

    if (!PyArg_ParseTuple(args, "s:set", &addr))
	return NULL;
    if (getaddrinfo(addr, NULL, &hints, &res)) {
	hints.ai_flags = 0;
	if (getaddrinfo(addr, NULL, &hints, &res))
	    PyRFC3542_perror("set: invalid hostname or IPv6 address");
    }
    memset((void *) &self->nexthop->sin6_addr, 0, sizeof(struct in6_addr));
    memcpy((void *) &self->nexthop->sin6_addr,
	   (void *) &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
	   sizeof(struct in6_addr));
    freeaddrinfo(res);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(nexthop_set_doc,
"set(string) -> None\n\
\n\
Initialize a NEXTHOP object. Arg1 is the next hop address.\n\
Return None.");

static PyObject *
PyNEXTHOP_set_from_data(PyNEXTHOPObject *self, PyObject *args)
{
    char *data;
    int datalen;

    if (!PyArg_ParseTuple(args, "s#:set_from_data", &data, &datalen))
	return NULL;
    if (datalen != sizeof(struct sockaddr_in6))
	PyRFC3542_perror("set_from_data: data has bad length");
    memset((void *) self->nexthop, 0, sizeof(struct sockaddr_in6));
    memcpy((void *) self->nexthop, (void *) data, datalen);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(nexthop_set_from_data_doc,
"set_from_data(string) -> None\n\
\n\
Initialize NEXTHOP object from raw data (arg1)\n\
Return None.");

static PyObject *
PyNEXTHOP_get(PyNEXTHOPObject *self)
{
    char host[NI_MAXHOST];

    if (getnameinfo((struct sockaddr *) self->nexthop,
		    sizeof(struct sockaddr_in6), host, NI_MAXHOST,
		    NULL, 0, NI_NUMERICHOST))
	PyRFC3542_perror("get: invalid IPv6 address in nexthop");
    return Py_BuildValue("s", host);
}

PyDoc_STRVAR(nexthop_get_doc,
"get() -> string\n\
\n\
Return next hop address.");

static PyMethodDef PyNEXTHOP_methods[] = {
    {"set", (PyCFunction) PyNEXTHOP_set,
     METH_VARARGS, nexthop_set_doc},
    {"set_from_data", (PyCFunction) PyNEXTHOP_set_from_data,
     METH_VARARGS, nexthop_set_from_data_doc},
    {"get", (PyCFunction) PyNEXTHOP_get,
     METH_NOARGS, nexthop_get_doc},
    {NULL, NULL, 0, NULL}
};

static PyObject *
PyNEXTHOP_getattr(PyNEXTHOPObject *self, char *name)
{
    if (!strcmp(name, "data"))
	return PyString_FromStringAndSize(
	    (char *) self->nexthop, sizeof(struct sockaddr_in6));
    if (!strcmp(name, "size"))
	return Py_BuildValue("i", sizeof(struct sockaddr_in6));
    return Py_FindMethod(PyNEXTHOP_methods, (PyObject *) self, name);
}

static void
PyNEXTHOP_dealloc(PyNEXTHOPObject *self)
{
    PyMem_Free(self->nexthop);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyNEXTHOP_repr(PyNEXTHOPObject *self)
{
    char buf[512];
    PyObject *p = PyNEXTHOP_get(self);

    if (p == NULL)
	return NULL;
    PyOS_snprintf(buf, sizeof(buf), "<nexthop object, addr='%s'>",
		  PyString_AS_STRING(p));
    Py_DECREF(p);
    return PyString_FromString(buf);
}

PyDoc_STRVAR(nexthop_object_doc,
"NEXTHOP objects are defined to handle next hop address option\n\
\n\
nexthop() -> NEXTHOP object\n\
\n\
Create a new NEXTHOP object\n\
\n\
Methods of NEXTHOP objects:\n\
\n\
set(string) -- set the next hop address\n\
set_from_data(string) -- set the next hop address from raw data\n\
get() -- return next hop address\n\
\n\
Attributes of NEXTHOP objects:\n\
\n\
data -- NEXTHOP object as a raw string\n\
size -- size in bytes of `nexthop' option (not NEXTHOP object)");

static PyTypeObject PyNEXTHOP_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "rfc3542.nexthop",				/* tp_name */
    sizeof(PyNEXTHOPObject),			/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyNEXTHOP_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyNEXTHOP_getattr,		/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc) PyNEXTHOP_repr,			/* tp_repr */
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
    nexthop_object_doc,				/* tp_doc */
};
#endif /* IPV6_NEXTHOP */

/*****************************************************************************
 * IP6_MTUINFO OBJECT METHODS
 *****************************************************************************/

#if defined(HAVE_STRUCT_IP6_MTUINFO) && defined(IPV6_PATHMTU)
static PyObject *
PyIP6_MTUINFO_set(PyIP6_MTUINFOObject *self, PyObject *args)
{
    unsigned int mtu;
    char *addr;
    struct addrinfo hints = {AI_NUMERICHOST, AF_INET6}, *res;

    if (!PyArg_ParseTuple(args, "sI:set", &addr, &mtu))
	return NULL;
    if (getaddrinfo(addr, NULL, &hints, &res)) {
	hints.ai_flags = 0;
	if (getaddrinfo(addr, NULL, &hints, &res))
	    PyRFC3542_perror("set: invalid hostname or IPv6 address");
    }
    memset((void *) self->mtuinfo, 0, sizeof(struct ip6_mtuinfo));
    memcpy((void *) &self->mtuinfo->ip6m_addr,
	   (void *) &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
	   sizeof(struct in6_addr));
    self->mtuinfo->ip6m_mtu = mtu;
    freeaddrinfo(res);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(ip6_mtuinfo_set_doc,
"set(string, int) -> None\n\
\n\
Initialize a IP6_MTUINFO object. Arg1 is destination address including\n\
zone ID, arg2 is path MTU in host byte order. Return None.");

static PyObject *
PyIP6_MTUINFO_set_from_data(PyIP6_MTUINFOObject *self, PyObject *args)
{
    char *data;
    int datalen;

    if (!PyArg_ParseTuple(args, "s#:set_from_data", &data, &datalen))
	return NULL;
    if (datalen != sizeof(struct ip6_mtuinfo))
	PyRFC3542_perror("set_from_data: data has bad length");
    memset((void *) self->mtuinfo, 0, sizeof(struct ip6_mtuinfo));
    memcpy((void *) self->mtuinfo, (void *) data, datalen);
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(ip6_mtuinfo_set_from_data_doc,
"set_from_data(string) -> None\n\
\n\
Initialize IP6_MTUINFO object from raw data (arg1)\n\
Return None.");

static PyObject *
PyIP6_MTUINFO_get(PyIP6_MTUINFOObject *self)
{
    char host[NI_MAXHOST];
    struct sockaddr_in6 sin6;

    memset((void *) &sin6, 0, sizeof(sin6));
#ifdef HAVE_SOCKADDR_SA_LEN
    sin6.sin6_len = sizeof(sin6);
#endif
    sin6.sin6_family = AF_INET6;
    memcpy((void *) &sin6.sin6_addr, (void *) &self->mtuinfo->ip6m_addr,
	   sizeof(struct in6_addr));
    if (getnameinfo((struct sockaddr *) &sin6, sizeof(sin6), host, NI_MAXHOST,
		    NULL, 0, NI_NUMERICHOST))
	PyRFC3542_perror("get: invalid IPv6 address in mtuinfo");
    return Py_BuildValue("si", host, self->mtuinfo->ip6m_mtu);
}

PyDoc_STRVAR(ip6_mtuinfo_get_doc,
"get() -> (string, int)\n\
\n\
Return (`destination address', `path MTU').");

static PyMethodDef PyIP6_MTUINFO_methods[] = {
    {"set", (PyCFunction) PyIP6_MTUINFO_set,
     METH_VARARGS, ip6_mtuinfo_set_doc},
    {"set_from_data", (PyCFunction) PyIP6_MTUINFO_set_from_data,
     METH_VARARGS, ip6_mtuinfo_set_from_data_doc},
    {"get", (PyCFunction) PyIP6_MTUINFO_get,
     METH_NOARGS, ip6_mtuinfo_get_doc},
    {NULL, NULL, 0, NULL}
};

static void
PyIP6_MTUINFO_dealloc(PyIP6_MTUINFOObject *self)
{
    PyMem_Free(self->mtuinfo);
    PyObject_Del((PyObject *) self);
}

static PyObject *
PyIP6_MTUINFO_getattr(PyIP6_MTUINFOObject *self, char *name)
{
    if (!strcmp(name, "data"))
	return PyString_FromStringAndSize(
	    (char *) self->mtuinfo, sizeof(struct ip6_mtuinfo));
    if (!strcmp(name, "size"))
	return Py_BuildValue("i", sizeof(struct ip6_mtuinfo));
    return Py_FindMethod(PyIP6_MTUINFO_methods, (PyObject *) self, name);
}

static PyObject *
PyIP6_MTUINFO_repr(PyIP6_MTUINFOObject *self)
{
    PyObject *p = PyIP6_MTUINFO_get(self);
    char *addr, buf[512];
    unsigned long ifindex;

    if (p == NULL)
	return NULL;
    addr = PyString_AS_STRING(PyTuple_GET_ITEM(p, 0));
    ifindex = PyInt_AsUnsignedLongMask(PyTuple_GET_ITEM(p, 1));
    PyOS_snprintf(
	buf, sizeof(buf), "<ip6_mtuinfo object, addr='%s', mtu=%lu>",
	addr, ifindex);
    Py_DECREF(p);
    return PyString_FromString(buf);
}

PyDoc_STRVAR(ip6_mtuinfo_object_doc,
"IP6_MTUINFO objects are defined to handle path MTU option\n\
\n\
ip6_mtuinfo() -> IP6_MTUINFO object\n\
\n\
Create a new IP6_MTUINFO object\n\
\n\
Methods of IP6_MTUINFO objects:\n\
\n\
set(string, int) -- initialize a path MTU option\n\
set_from_data(string) -- initialize a path MTU option from raw data\n\
get() -- return a path MTU option as a 2-tuple (`destination address',\n\
  `path MTU')\n\
\n\
Attributes of IP6_MTUINFO objects:\n\
\n\
data -- IP6_MTUINFO object as a raw string\n\
size -- size in bytes of `ip6_mtuinfo' option (not IP6_MTUINFO object)");

static PyTypeObject PyIP6_MTUINFO_Type = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "rfc3542.ip6_mtuinfo",			/* tp_name */
    sizeof(PyIP6_MTUINFOObject),		/* tp_basicsize */
    0,						/* tp_itemsize */
    /* methods */
    (destructor) PyIP6_MTUINFO_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    (getattrfunc) PyIP6_MTUINFO_getattr,	/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc) PyIP6_MTUINFO_repr,		/* tp_repr */
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
    ip6_mtuinfo_object_doc,			/* tp_doc */
};
#endif /* HAVE_STRUCT_IP6_MTUINFO, ... */

/*****************************************************************************
 * MODULE METHODS
 *****************************************************************************/

/* Routing header constructor and functions */

#ifdef IPV6_RTHDR
static PyObject *
PyRFC3542_inet6_rth(PyObject *self)
{
    PyINET6_RTHObject *p;

    p = PyObject_New(PyINET6_RTHObject, &PyINET6_RTH_Type);
    if (p == NULL)
	PyRFC3542_perror("inet6_rth: PyObject_New failed");
    p->rth = (struct ip6_rthdr **) &p->bp;
    p->bp = NULL;
    p->bp_len = 0;
    return (PyObject *) p;
}

PyDoc_STRVAR(inet6_rth_doc,
"inet6_rth() -> INET6_RTH object\n\
\n\
Create a new INET6_RTH object.");

static PyObject *
PyRFC3542_inet6_rth_space(PyObject *self, PyObject *args)
{
    int type, segments;

    if (!PyArg_ParseTuple(args, "ii:inet6_rth_space", &type, &segments))
	return NULL;
    return Py_BuildValue("i", inet6_rth_space(type, segments));
}

PyDoc_STRVAR(inet6_rth_space_doc,
"inet6_rth_space(int, int) -> int\n\
\n\
First argument should be the constant IPV6_RTHDR_TYPE_0 (0), second\n\
argument is the number of segments. Return the number of bytes required\n\
to hold a routing header the specified number of segments (arg2). See\n\
RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_rth_init(PyObject *self, PyObject *args)
{
    int type, segments;
    PyINET6_RTHObject *rp;

    if (!PyArg_ParseTuple(
	    args, "O!ii:inet6_rth_init", &PyINET6_RTH_Type, (PyObject *) &rp,
	    &type, &segments))
	return NULL;
    if (PyINET6_RTH_set(rp, Py_BuildValue("ii", type, segments)) == NULL)
	return NULL;
    Py_INCREF(rp);
    return (PyObject *) rp;
}

PyDoc_STRVAR(inet6_rth_init_doc,
"inet6_rth_init(INET6_RTH, int, int) -> INET6_RTH\n\
\n\
First argument is the INET6_RTH object to initialize. Second argument\n\
should be the constant IPV6_RTHDR_TYPE_0 (0). Last argument is the number\n\
of segments. Return new reference to first argument. See RFC3542 for more\n\
details.");

static PyObject *
PyRFC3542_inet6_rth_add(PyObject *self, PyObject *args)
{
    int ret;
    char *ta;
    struct addrinfo hints = {AI_NUMERICHOST, AF_INET6}, *res;
    PyINET6_RTHObject *rp;

    if (!PyArg_ParseTuple(
	    args, "O!s:inet6_rth_add", &PyINET6_RTH_Type, (PyObject *) &rp,
	    &ta))
	return NULL;
    if (getaddrinfo(ta, NULL, &hints, &res)) {
	hints.ai_flags = 0;
	if (getaddrinfo(ta, NULL, &hints, &res))
	    PyRFC3542_perror(
		"inet6_rth_add: invalid hostname or IPv6 address");
    }
    if (rp->bp_len <
	inet6_rth_space((*rp->rth)->ip6r_type, (*rp->rth)->ip6r_segleft + 1))
	PyRFC3542_perror(
		"inet6_rth_add: routing header size is too small");
    ret = inet6_rth_add(rp->bp,
			&((struct sockaddr_in6 *) res->ai_addr)->sin6_addr);
    freeaddrinfo(res);
    if (ret == -1)
	PyRFC3542_perror("inet6_rth_add failed");
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(inet6_rth_add_doc,
"inet6_rth_add(INET6_RTH, string) -> None\n\
\n\
Add a segment (arg2) to the end of a INET6_RTH object (arg1). Return None.\n\
See RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_rth_segments(PyObject *self, PyObject *args)
{
    int ret;
    PyINET6_RTHObject *rp;

    if (!PyArg_ParseTuple(args, "O!:inet6_rth_segments",
			  &PyINET6_RTH_Type, (PyObject *) &rp))
	return NULL;
    ret = inet6_rth_segments(rp->bp);
    if (ret == -1)
	PyRFC3542_perror("inet6_rth_segments failed");
    return Py_BuildValue("i", ret);
}

PyDoc_STRVAR(inet6_rth_segments_doc,
"inet6_rth_segments(INET6_RTH) -> int\n\
\n\
Return the number of segments contained in a INET6_RTH object (arg1). See\n\
RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_rth_reverse(PyObject *self, PyObject *args)
{
    int ret;
    PyINET6_RTHObject *in, *out;

    if (!PyArg_ParseTuple(args, "O!O!:inet6_rth_reverse",
			  &PyINET6_RTH_Type, (PyObject *) &in,
			  &PyINET6_RTH_Type, (PyObject *) &out))
	return NULL;
    if (in != out) {
	int type = (*in->rth)->ip6r_type, segments = (*in->rth)->ip6r_len >> 1;

	if (PyRFC3542_inet6_rth_init(
		self, Py_BuildValue("Oii", out, type, segments)) == NULL)
	    return NULL;
    }
    ret = inet6_rth_reverse(in->bp, out->bp);
    if (ret == -1)
	PyRFC3542_perror("inet6_rth_reverse failed");
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(inet6_rth_reverse_doc,
"inet6_rth_reverse(INET6_RTH, INET6_RTH) -> None\n\
\n\
Reverse an INET6_RTH object (arg1) and put the result in arg2. Arg1 and\n\
arg2 can be references to the same INET6_RTH object (reversal occur in\n\
place). Return None. See RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_rth_getaddr(PyObject *self, PyObject *args)
{
    int idx;
    char host[NI_MAXHOST];
    struct in6_addr *ret;
    struct sockaddr_in6 sin6 = {
#ifdef HAVE_SOCKADDR_SA_LEN
	sizeof(sin6),
#endif
	AF_INET6,
	0,
	0
    };
    PyINET6_RTHObject *rp;

    if (!PyArg_ParseTuple(args, "O!i:inet6_rth_getaddr",
			  &PyINET6_RTH_Type, (PyObject *) &rp, &idx))
	return NULL;
    ret = inet6_rth_getaddr(rp->bp, idx);
    if (ret == NULL)
	PyRFC3542_perror("inet6_rth_getaddr failed");
    memcpy((void *) &sin6.sin6_addr, (void *) ret, sizeof(struct in6_addr));
    sin6.sin6_scope_id = 0;
    if (getnameinfo((struct sockaddr *) &sin6, sizeof(sin6),
		    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
	PyRFC3542_perror("inet6_rth_getaddr returns garbage");
    return Py_BuildValue("s", host);
}

PyDoc_STRVAR(inet6_rth_getaddr_doc,
"inet6_rth_getaddr(INET6_RTH, int) -> string\n\
\n\
Return segment specified by index (arg2) in INET6_RTH object (arg1). See\n\
RFC3542 for more details.");
#endif /* IPV6_RTHDR */

/* Option constructor and functions */

#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
static PyObject *
PyRFC3542_inet6_opt(PyObject *self)
{
    PyINET6_OPTObject *p;

    p = PyObject_New(PyINET6_OPTObject, &PyINET6_OPT_Type);
    if (p == NULL)
	PyRFC3542_perror("inet6_opt: PyObject_New failed");
    p->opt = (struct ip6_opt **) &p->extbuf;
    p->extbuf = NULL;
    p->extlen = 0;
    p->databuf = NULL;
    return (PyObject *) p;
}

PyDoc_STRVAR(inet6_opt_doc,
"inet6_opt() -> INET6_OPT object\n\
\n\
Create a new INET6_OPT object.");

static PyObject *
PyRFC3542_inet6_opt_init(PyObject *self, PyObject *args)
{
    int ret;
    void *extbuf = NULL;
    socklen_t extlen = 0;
    PyINET6_OPTObject *op = NULL;

    if (!PyArg_ParseTuple(
	    args, "|O!i:inet6_opt_init", &PyINET6_OPT_Type, (PyObject *) &op,
	    &extlen))
	return NULL;
    if (op != NULL)
	extbuf = op->extbuf;
    if ((ret = inet6_opt_init(extbuf, extlen)) == -1)
	PyRFC3542_perror("inet6_opt_init failed");	
    return Py_BuildValue("i", ret);
}

PyDoc_STRVAR(inet6_opt_init_doc,
"inet6_opt_init([INET6_OPT, int]) -> int\n\
\n\
Without arguments, return the number of bytes needed for the empty\n\
extension header i.e., without any options. With arguments, inet6_opt_init\n\
also initializes INET6_OPT object (arg1) to have correct length (arg2).\n\
Arg2 must be a positive multiple of 8. See RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_opt_append(PyObject *self, PyObject *args)
{
    int offset, ret;
    uint8_t type, align;
    socklen_t len, extlen = 0;
    void *extbuf = NULL, **databuf = NULL;
    PyINET6_OPTObject *op = NULL;

    if (!PyArg_ParseTuple(
	    args, "O!iBiB:inet6_opt_append", &PyINET6_OPT_Type,
	    (PyObject *) &op, &offset, &type, &len, &align)) {
	PyErr_Clear();
	if (!PyArg_ParseTuple(
		args, "iBiB:inet6_opt_append", &offset, &type, &len, &align))
	    return NULL;
    }
    if (op != NULL) {
	extbuf = op->extbuf;
	extlen = op->extlen;
	databuf = &op->databuf;
    }
    ret = inet6_opt_append(extbuf, extlen, offset, type, len, align, databuf);
    if (ret == -1)
	PyRFC3542_perror("inet6_opt_append failed");
    return Py_BuildValue("i", ret);
}

PyDoc_STRVAR(inet6_opt_append_doc,
"inet6_opt_append([INET6_OPT, ]int, int, int, int) -> int\n\
\n\
Arg2 should be the length returned by inet6_opt_init() or a previous\n\
inet6_opt_append(). Return the updated total length taking into account\n\
adding an option with length arg4 and alignment arg5. If INET6_OPT object\n\
is given as arg1, this function also inserts any needed pad option and\n\
initializes the option in arg1.\n\
Arg3 is the 8-bit option type and must have a value from 2 to 255,\n\
inclusive. Arg4 must have a value between 0 and 255, inclusive. Arg5 must\n\
have a value of 1, 2, 4, or 8 and can not exceed the value of arg4. See\n\
RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_opt_finish(PyObject *self, PyObject *args)
{
    int offset, ret;
    socklen_t extlen = 0;
    void *extbuf = NULL;
    PyINET6_OPTObject *op = NULL;

    if (!PyArg_ParseTuple(
	    args, "O!i:inet6_opt_finish", &PyINET6_OPT_Type, (PyObject *) &op,
	    &offset)) {
	PyErr_Clear();
	if (!PyArg_ParseTuple(args, "i:inet6_opt_finish", &offset))
	    return NULL;
    }
    if (op != NULL) {
	extbuf = op->extbuf;
	extlen = op->extlen;
    }
    if ((ret = inet6_opt_finish(extbuf, extlen, offset)) == -1)
	PyRFC3542_perror("inet6_opt_finish failed");
    if (op != NULL)
	op->databuf = NULL;
    return Py_BuildValue("i", ret);
}

PyDoc_STRVAR(inet6_opt_finish_doc,
"inet6_opt_finish([INET6_OPT, ]int) -> int\n\
\n\
Arg2 should be the length returned by inet6_opt_init() or\n\
inet6_opt_append(). This function returns the updated total length\n\
taking into account the final padding of the extension header to make it\n\
a multiple of 8 bytes. If INET6_OPT object is given as arg1, this\n\
function also initializes the option by inserting a Pad1 or PadN option\n\
of the proper length in arg1. See RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_opt_set_val(PyObject *self, PyObject *args)
{
    int offset, ret;
    void *val;
    socklen_t vallen;
    PyINET6_OPTObject *op;

    if (!PyArg_ParseTuple(
	    args, "O!is#:inet6_opt_set_val", &PyINET6_OPT_Type,
	    (PyObject *) &op, &offset, (char *) &val, &vallen))
	return NULL;
    if (op->extbuf == NULL)
	PyRFC3542_perror(
	    "inet6_opt_set_val: arg1 must be initialized with method set");
    if (op->databuf == NULL)
	PyRFC3542_perror(
	    "inet6_opt_set_val: arg1 not initialized with inet6_opt_append");
    if (vallen == 0)
	PyRFC3542_perror("inet6_opt_set_val: data are empty");
    ret = inet6_opt_set_val(op->databuf, offset, val, vallen);
    return Py_BuildValue("i", ret);
}

PyDoc_STRVAR(inet6_opt_set_val_doc,
"inet6_opt_set_val(INET6_OPT, int, string) -> int\n\
\n\
Insert data (arg3) items of various sizes in the data portion of the option\n\
(arg1). Arg2 specifies where in the data portion of the option the value\n\
should be inserted; the first byte after the option type and length is\n\
accessed by specifying an offset (arg2) of zero.\n\
Return the offset for the next field which can be used when composing\n\
option content with multiple fields. See RFC3542 for more details.");

static PyObject *
PyRFC3542_inet6_opt_next(PyObject *self, PyObject *args)
{
    int offset, ret;
    uint8_t type;
    socklen_t len;
    PyINET6_OPTObject *op;

    if (!PyArg_ParseTuple(
	    args, "O!i:inet6_opt_next", &PyINET6_OPT_Type, (PyObject *) &op,
	    &offset))
	return NULL;
    if (op->extbuf == NULL)
	PyRFC3542_perror(
	    "inet6_opt_next: arg1 must be initialized with method set");
    ret = inet6_opt_next(op->extbuf, op->extlen, offset, &type, &len,
			 &op->databuf);
    if (ret == -1)
	PyRFC3542_perror("inet6_opt_next failed");
    return Py_BuildValue("iii", ret, type, len);
}

PyDoc_STRVAR(inet6_opt_next_doc,
"inet6_opt_next(INET6_OPT, int) -> (int, int, int)\n\
\n\
Parse option extension header (arg1). Arg2 should either be zero (for the\n\
first option) or the length returned by a previous call to inet6_opt_next()\n\
or inet6_opt_find().\n\
Return next option as the 3-tuple (type, length, offset). See RFC3542 for\n\
more details.");

static PyObject *
PyRFC3542_inet6_opt_find(PyObject *self, PyObject *args)
{
    int offset, ret;
    uint8_t type;
    socklen_t len;
    PyINET6_OPTObject *op;

    if (!PyArg_ParseTuple(
	    args, "O!iB:inet6_opt_find", &PyINET6_OPT_Type, (PyObject *) &op,
	    &offset, &type))
	return NULL;
    if (op->extbuf == NULL)
	PyRFC3542_perror(
	    "inet6_opt_find: arg1 must be initialized with method set");
    ret = inet6_opt_find(op->extbuf, op->extlen, offset, type, &len,
			 &op->databuf);
    if (ret == -1)
	PyRFC3542_perror("inet6_opt_find failed");
    return Py_BuildValue("ii", ret, len);
}

PyDoc_STRVAR(inet6_opt_find_doc,
"inet6_opt_find(INET6_OPT, int, int) -> (int, int)\n\
\n\
Similar to `inet6_opt_next' method, except this method lets the caller\n\
specify the option type (arg2) to be searched for. See RFC3542 for more\n\
details.");

static PyObject *
PyRFC3542_inet6_opt_get_val(PyObject *self, PyObject *args)
{
    int offset, r;
    void *val;
    socklen_t vallen;
    PyObject *ret;
    PyINET6_OPTObject *op;

    if (!PyArg_ParseTuple(
	    args, "O!ii:inet6_opt_get_val", &PyINET6_OPT_Type,
	    (PyObject *) &op, &offset, &vallen))
	return NULL;
    if (op->extbuf == NULL)
	PyRFC3542_perror(
	    "inet6_opt_get_val: arg1 must be initialized with method set");
    if (op->databuf == NULL)
	PyRFC3542_perror(
	    "inet6_opt_get_val: arg1 not initialized with inet6_opt_next/find"
	    );
    if (vallen <= 0)
	PyRFC3542_perror(
	    "inet6_opt_get_val: last argument must a positive integer");
    val = (void *) PyMem_New(unsigned char, vallen);
    if (val ==  NULL)
	return PyErr_NoMemory();
    r = inet6_opt_get_val(op->databuf, offset, val, vallen);
    ret = Py_BuildValue("is#", r, val, vallen);
    PyMem_Free(val);
    return ret;
}

PyDoc_STRVAR(inet6_opt_get_val_doc,
"inet6_opt_get_val(INET6_OPT, int, int) -> (int, string)\n\
\n\
Extract data form INET6_OPT object (arg1). Arg2 specifies from where in\n\
the data portion of the option the value should be extracted; the first\n\
byte after the option type and length is accessed by specifying an offset\n\
of zero. Arg3 is the size in bytes of the data to extract.\n\
Return offset for the next field and data extracted (as a 2-tuple). See\n\
RFC3542 for more details.");
#endif /* IPV6_HOPOPTS, ... */

/* Constructors for ICMP6_FILTER, in6_pktinfo, nexthop and
 * ip6_mtuinfo objects */

#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)
static PyObject *
PyRFC3542_icmp6_filter(PyObject *self)
{
    PyICMP6_FILTERObject *f;

    f = PyObject_New(PyICMP6_FILTERObject, &PyICMP6_FILTER_Type);
    if (f == NULL)
	PyRFC3542_perror("icmp6_filter: PyObject_New failed");
    f->filter = PyMem_New(struct icmp6_filter, 1);
    if (f->filter ==  NULL) {
	Py_DECREF(f);
	return PyErr_NoMemory();
    }
    memset((void *) f->filter, 0, sizeof(struct icmp6_filter));
    return (PyObject *) f;
}

PyDoc_STRVAR(icmp6_filter_doc,
"icmp6_filter() -> ICMP6_FILTER object\n\
\n\
Create a new ICMP6_FILTER object.");
#endif /* HAVE_STRUCT_ICMP6_FILTER, ... */

#if defined(HAVE_STRUCT_IN6_PKTINFO) && defined(IPV6_PKTINFO)
static PyObject *
PyRFC3542_in6_pktinfo(PyObject *self)
{
    PyIN6_PKTINFOObject *p;

    p = PyObject_New(PyIN6_PKTINFOObject, &PyIN6_PKTINFO_Type);
    if (p == NULL)
	PyRFC3542_perror("in6_pktinfo: PyObject_New failed");
    p->pktinfo = PyMem_New(struct in6_pktinfo, 1);
    if (p->pktinfo ==  NULL) {
	Py_DECREF(p);
	return PyErr_NoMemory();
    }
    memset((void *) p->pktinfo, 0, sizeof(struct in6_pktinfo));
    return (PyObject *) p;
}

PyDoc_STRVAR(in6_pktinfo_doc,
"in6_pktinfo() -> IN6_PKTINFO object\n\
\n\
Create an new IN6_PKTINFO object.");
#endif /* HAVE_STRUCT_IN6_PKTINFO, ... */

#ifdef IPV6_NEXTHOP
static PyObject *
PyRFC3542_nexthop(PyObject *self)
{
    PyNEXTHOPObject *p;

    p = PyObject_New(PyNEXTHOPObject, &PyNEXTHOP_Type);
    if (p == NULL)
	PyRFC3542_perror("nexthop: PyObject_New failed");
    p->nexthop = PyMem_New(struct sockaddr_in6, 1);
    if (p->nexthop ==  NULL) {
	Py_DECREF(p);
	return PyErr_NoMemory();
    }
    memset((void *) p->nexthop, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_SOCKADDR_SA_LEN
        p->nexthop->sin6_len = sizeof(struct sockaddr_in6);
#endif
        p->nexthop->sin6_family = AF_INET6;
    return (PyObject *) p;
}

PyDoc_STRVAR(nexthop_doc,
"nexthop() -> NEXTHOP object\n\
\n\
Create a new NEXTHOP object.");
#endif /* IPV6_NEXTHOP */

#if defined(HAVE_STRUCT_IP6_MTUINFO) && defined(IPV6_PATHMTU)
static PyObject *
PyRFC3542_ip6_mtuinfo(PyObject *self)
{
    PyIP6_MTUINFOObject *p;

    p = PyObject_New(PyIP6_MTUINFOObject, &PyIP6_MTUINFO_Type);
    if (p == NULL)
	PyRFC3542_perror("ip6_mtuinfo: PyObject_New failed");
    p->mtuinfo = PyMem_New(struct ip6_mtuinfo, 1);
    if (p->mtuinfo ==  NULL) {
	Py_DECREF(p);
	return PyErr_NoMemory();
    }
    memset((void *) p->mtuinfo, 0, sizeof(struct ip6_mtuinfo));
    return (PyObject *) p;
}

PyDoc_STRVAR(ip6_mtuinfo_doc,
"ip6_mtuinfo() -> IP6_MTUINFO object\n\
\n\
Create a new IP6_MTUINFO object.");
#endif /* HAVE_STRUCT_IP6_MTUINFO, ... */

#ifndef IP6OPT_TYPE
#define IP6OPT_TYPE(o) ((o) & 0xc0)
#endif

/* Miscellaneous */

static PyObject *
PyRFC3542_IP6OPT_TYPE(PyObject *self, PyObject *args)
{
    uint8_t type;

    if (!PyArg_ParseTuple(args, "B:IP6OPT_TYPE", &type))
	return NULL;
    return Py_BuildValue("i", IP6OPT_TYPE(type));
}

PyDoc_STRVAR(IP6OPT_TYPE_doc,
"IP6OPT_TYPE(int) -> int\n\
\n\
Return high-order 3 bits of the option type (arg1)");

static PyMethodDef PyRFC3542_methods[] = {
#ifdef IPV6_RTHDR
    {"inet6_rth", (PyCFunction) PyRFC3542_inet6_rth,
     METH_NOARGS, inet6_rth_doc},
    {"inet6_rth_space", (PyCFunction) PyRFC3542_inet6_rth_space,
     METH_VARARGS, inet6_rth_space_doc},
    {"inet6_rth_init", (PyCFunction) PyRFC3542_inet6_rth_init,
     METH_VARARGS, inet6_rth_init_doc},
    {"inet6_rth_add", (PyCFunction) PyRFC3542_inet6_rth_add,
     METH_VARARGS, inet6_rth_add_doc},
    {"inet6_rth_segments", (PyCFunction) PyRFC3542_inet6_rth_segments,
     METH_VARARGS, inet6_rth_segments_doc},
    {"inet6_rth_reverse", (PyCFunction) PyRFC3542_inet6_rth_reverse,
     METH_VARARGS, inet6_rth_reverse_doc},
    {"inet6_rth_getaddr", (PyCFunction) PyRFC3542_inet6_rth_getaddr,
     METH_VARARGS, inet6_rth_getaddr_doc},
#endif /* IPV6_RTHDR */
#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
    {"inet6_opt", (PyCFunction) PyRFC3542_inet6_opt,
     METH_NOARGS, inet6_opt_doc},
    {"inet6_opt_init", (PyCFunction) PyRFC3542_inet6_opt_init,
     METH_VARARGS, inet6_opt_init_doc},
    {"inet6_opt_append", (PyCFunction) PyRFC3542_inet6_opt_append,
     METH_VARARGS, inet6_opt_append_doc},
    {"inet6_opt_finish", (PyCFunction) PyRFC3542_inet6_opt_finish,
     METH_VARARGS, inet6_opt_finish_doc},
    {"inet6_opt_set_val", (PyCFunction) PyRFC3542_inet6_opt_set_val,
     METH_VARARGS, inet6_opt_set_val_doc},
    {"inet6_opt_next", (PyCFunction) PyRFC3542_inet6_opt_next,
     METH_VARARGS, inet6_opt_next_doc},
    {"inet6_opt_find", (PyCFunction) PyRFC3542_inet6_opt_find,
     METH_VARARGS, inet6_opt_find_doc},
    {"inet6_opt_get_val", (PyCFunction) PyRFC3542_inet6_opt_get_val,
     METH_VARARGS, inet6_opt_get_val_doc},
#endif /* IPV6_HOPOPTS, ... */
#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)
    {"icmp6_filter", (PyCFunction) PyRFC3542_icmp6_filter,
     METH_NOARGS, icmp6_filter_doc},
#endif /* HAVE_STRUCT_ICMP6_FILTER, ... */
#if defined(HAVE_STRUCT_IN6_PKTINFO) && defined(IPV6_PKTINFO)
    {"in6_pktinfo", (PyCFunction) PyRFC3542_in6_pktinfo,
     METH_NOARGS, in6_pktinfo_doc},
#endif /* HAVE_STRUCT_IP6_PKTNFO, ... */
#ifdef IPV6_NEXTHOP
    {"nexthop", (PyCFunction) PyRFC3542_nexthop,
     METH_NOARGS, nexthop_doc},
#endif /* IPV6_NEXTHOP */
#if defined(HAVE_STRUCT_IP6_MTUINFO) && defined(IPV6_PATHMTU)
    {"ip6_mtuinfo", (PyCFunction) PyRFC3542_ip6_mtuinfo,
     METH_NOARGS, ip6_mtuinfo_doc},
#endif /* HAVE_STRUCT_IP6_MTUINFO, ... */
    {"IP6OPT_TYPE", (PyCFunction) PyRFC3542_IP6OPT_TYPE,
     METH_VARARGS, IP6OPT_TYPE_doc},
    {NULL, NULL, 0, NULL}
};

/*****************************************************************************
 * MODULE INITIALIZATION
 *****************************************************************************/

PyDoc_STRVAR(rfc3542_doc,
"`rfc3542' is a full implementation of RFC3542 (Advanced Sockets Application\n\
Program Interface (API) for IPv6).\n\
\n\
`rfc3542' module defines a new object for each option defined in RFC3542:\n\
- HOPLIMIT object -- hop limit option\n\
- TCLASS object -- traffic class option\n\
- INET6_RTH object -- routing header\n\
- INET6_OPT object -- extension header\n\
- ICMP6_FILTER object -- ICMPv6 filter\n\
- IN6_PKTINFO object -- packet information option\n\
- NEXTHOP object -- next hop address option\n\
- IP6_MTUINFO object -- path MTU option\n\
Each object has at least the following 3 methods:\n\
- set -- initialize option\n\
- set_from_data --  initialize option from raw data\n\
- get -- return object data\n\
and, in addition, at least the following attribute:\n\
- data -- object as a raw string\n\
Some objects have also attribute:\n\
- size -- size in bytes of corresponding option (NOT object size)\n\
\n\
Methods of `rfc3542' module are:\n\
\n\
- constructors: hoplimit, tclass, inet6_rth, inet6_opt, icmp6_filter,\n\
  in6_pktinfo, nexthop and ip6_mtuinfo\n\
- inet6_rth_XXX functions: inet6_rth_space, inet6_rth_init, inet6_rth_add,\n\
  inet6_rth_segments, inet6_rth_reverse and inet6_rth_getaddr\n\
- inet6_opt_XXX functions: inet6_opt_init, inet6_opt_append,\n\
  inet6_opt_finish, inet6_opt_set_val, inet6_opt_next, inet6_opt_find and\n\
  inet6_opt_get_val\n\
- IP6OPT_TYPE -- extracts high-order 3 bits of an option type");

PyMODINIT_FUNC
init_rfc3542(void)
{
    PyObject *m, *d;

#ifdef IPV6_RTHDR
    PyINET6_RTH_Type.ob_type = &PyType_Type;
#endif /* IPV6_RTHDR */
#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
    PyINET6_OPT_Type.ob_type = &PyType_Type;
#endif /* IPV6_HOPOPTS, ... */
#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)
    PyICMP6_FILTER_Type.ob_type = &PyType_Type;
#endif /* HAVE_STRUCT_ICMP6_FILTER, ... */
#if defined(HAVE_STRUCT_IN6_PKTINFO) && defined(IPV6_PKTINFO)
    PyIN6_PKTINFO_Type.ob_type = &PyType_Type;
#endif /* HAVE_STRUCT_IN6_PKTINFO, ... */
#ifdef IPV6_NEXTHOP
    PyNEXTHOP_Type.ob_type = &PyType_Type;
#endif /* IPV6_NEXTHOP */
#if defined(HAVE_STRUCT_IP6_MTUINFO) && defined(IPV6_PATHMTU)
    PyIP6_MTUINFO_Type.ob_type = &PyType_Type;
#endif /* HAVE_STRUCT_IP6_MTUINFO, ... */
    m = Py_InitModule3("_rfc3542", PyRFC3542_methods, rfc3542_doc);
    d = PyModule_GetDict(m);
    PyRFC3542_Error = PyErr_NewException("rfc3542.error", NULL, NULL);
    if (PyRFC3542_Error == NULL)
	return;
    Py_INCREF(PyRFC3542_Error);
    if (PyModule_AddObject(m, "error", PyRFC3542_Error) != 0)
	return;
/* Constants in <netinet/in.h> */
#ifdef IPPROTO_AH
    PyModule_AddIntConstant(m, "IPPROTO_AH", IPPROTO_AH);
#else
    PyModule_AddIntConstant(m, "IPPROTO_AH", 51);
#endif
#ifdef IPPROTO_DSTOPTS
    PyModule_AddIntConstant(m, "IPPROTO_DSTOPTS", IPPROTO_DSTOPTS);
#else
    PyModule_AddIntConstant(m, "IPPROTO_DSTOPTS", 60);
#endif
#ifdef IPPROTO_ESP
    PyModule_AddIntConstant(m, "IPPROTO_ESP", IPPROTO_ESP);
#else
    PyModule_AddIntConstant(m, "IPPROTO_ESP", 50);
#endif
#ifdef IPPROTO_FRAGMENT
    PyModule_AddIntConstant(m, "IPPROTO_FRAGMENT", IPPROTO_FRAGMENT);
#else
    PyModule_AddIntConstant(m, "IPPROTO_FRAGMENT", 44);
#endif
#ifdef IPPROTO_HOPOPTS
    PyModule_AddIntConstant(m, "IPPROTO_HOPOPTS", IPPROTO_HOPOPTS);
#else
    PyModule_AddIntConstant(m, "IPPROTO_HOPOPTS", 0);
#endif
#ifdef IPPROTO_ICMPV6
    PyModule_AddIntConstant(m, "IPPROTO_ICMPV6", IPPROTO_ICMPV6);
#else
    PyModule_AddIntConstant(m, "IPPROTO_ICMPV6", 58);
#endif
#ifdef IPPROTO_IPV6
    PyModule_AddIntConstant(m, "IPPROTO_IPV6", IPPROTO_IPV6);
#else
    PyModule_AddIntConstant(m, "IPPROTO_IPV6", 41);
#endif
#ifdef IPPROTO_NONE
    PyModule_AddIntConstant(m, "IPPROTO_NONE", IPPROTO_NONE);
#else
    PyModule_AddIntConstant(m, "IPPROTO_NONE", 59); 
#endif
#ifdef IPPROTO_ROUTING
    PyModule_AddIntConstant(m, "IPPROTO_ROUTING", IPPROTO_ROUTING);
#else
    PyModule_AddIntConstant(m, "IPPROTO_ROUTING", 43);
#endif
#ifdef IPV6_CHECKSUM
    PyModule_AddIntConstant(m, "IPV6_CHECKSUM", IPV6_CHECKSUM);
#endif
#ifdef IPV6_DONTFRAG
    PyModule_AddIntConstant(m, "IPV6_DONTFRAG", IPV6_DONTFRAG);
#endif
#ifdef IPV6_DSTOPTS
    PyModule_AddIntConstant(m, "IPV6_DSTOPTS", IPV6_DSTOPTS);
#endif
#ifdef IPV6_HOPLIMIT
    PyModule_AddIntConstant(m, "IPV6_HOPLIMIT", IPV6_HOPLIMIT);
#endif
#ifdef IPV6_HOPOPTS
    PyModule_AddIntConstant(m, "IPV6_HOPOPTS", IPV6_HOPOPTS);
#endif
#ifdef IPV6_NEXTHOP
    PyModule_AddIntConstant(m, "IPV6_NEXTHOP", IPV6_NEXTHOP);
#endif
#ifdef IPV6_PATHMTU
    PyModule_AddIntConstant(m, "IPV6_PATHMTU", IPV6_PATHMTU);
#endif
#ifdef IPV6_PKTINFO
    PyModule_AddIntConstant(m, "IPV6_PKTINFO", IPV6_PKTINFO);
#endif
#ifdef IPV6_RECVDSTOPTS
    PyModule_AddIntConstant(m, "IPV6_RECVDSTOPTS", IPV6_RECVDSTOPTS);
#else
#ifdef IPV6_DSTOPTS
    PyModule_AddIntConstant(m, "IPV6_RECVDSTOPTS", IPV6_DSTOPTS);
#endif
#endif
#ifdef IPV6_RECVHOPLIMIT
    PyModule_AddIntConstant(m, "IPV6_RECVHOPLIMIT", IPV6_RECVHOPLIMIT);
#else
#ifdef IPV6_HOPLIMIT
    PyModule_AddIntConstant(m, "IPV6_RECVHOPLIMIT", IPV6_HOPLIMIT);
#endif
#endif
#ifdef IPV6_RECVHOPOPTS
    PyModule_AddIntConstant(m, "IPV6_RECVHOPOPTS", IPV6_RECVHOPOPTS);
#else
#ifdef IPV6_HOPOPTS
    PyModule_AddIntConstant(m, "IPV6_RECVHOPOPTS", IPV6_HOPOPTS);
#endif
#endif
#ifdef IPV6_RECVPKTINFO
    PyModule_AddIntConstant(m, "IPV6_RECVPKTINFO", IPV6_RECVPKTINFO);
#else
#ifdef IPV6_PKTINFO
    PyModule_AddIntConstant(m, "IPV6_RECVPKTINFO", IPV6_PKTINFO);
#endif
#endif
#ifdef IPV6_RECVRTHDR
    PyModule_AddIntConstant(m, "IPV6_RECVRTHDR", IPV6_RECVRTHDR);
#else
#ifdef IPV6_RTHDR
    PyModule_AddIntConstant(m, "IPV6_RECVRTHDR", IPV6_RTHDR);
#endif
#endif
#ifdef IPV6_RECVTCLASS
    PyModule_AddIntConstant(m, "IPV6_RECVTCLASS", IPV6_RECVTCLASS);
#else
#ifdef IPV6_TCLASS
    PyModule_AddIntConstant(m, "IPV6_RECVTCLASS", IPV6_TCLASS);
#endif
#endif
#ifdef IPV6_RTHDR
    PyModule_AddIntConstant(m, "IPV6_RTHDR", IPV6_RTHDR);
#endif
#ifdef IPV6_RTHDRDSTOPTS
    PyModule_AddIntConstant(m, "IPV6_RTHDRDSTOPTS", IPV6_RTHDRDSTOPTS);
#endif
    PyModule_AddIntConstant(m, "IPV6_RTHDR_TYPE_0", 0);
#ifdef IPV6_RECVPATHMTU
    PyModule_AddIntConstant(m, "IPV6_RECVPATHMTU", IPV6_RECVPATHMTU);
#else
#ifdef IPV6_PATHMTU
    PyModule_AddIntConstant(m, "IPV6_RECVPATHMTU", IPV6_PATHMTU);
#endif
#endif
#ifdef IPV6_TCLASS
    PyModule_AddIntConstant(m, "IPV6_TCLASS", IPV6_TCLASS);
#endif
#ifdef IPV6_USE_MIN_MTU
    PyModule_AddIntConstant(m, "IPV6_USE_MIN_MTU", IPV6_USE_MIN_MTU);
#endif

/* Constants in <netinet/icmp6.h> */
#if defined(HAVE_STRUCT_ICMP6_FILTER) && defined(ICMP6_FILTER)
    PyModule_AddIntConstant(m, "ICMP6_FILTER", ICMP6_FILTER);
#endif
#ifdef ICMP6_DST_UNREACH
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH", ICMP6_DST_UNREACH);
#else
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH", 1);
#endif
#ifdef ICMP6_DST_UNREACH_ADDR
    PyModule_AddIntConstant(
	m, "ICMP6_DST_UNREACH_ADDR", ICMP6_DST_UNREACH_ADDR);
#else
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH_ADDR", 3);
#endif
#ifdef ICMP6_DST_UNREACH_ADMIN
    PyModule_AddIntConstant(
	m, "ICMP6_DST_UNREACH_ADMIN", ICMP6_DST_UNREACH_ADMIN);
#else
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH_ADMIN", 1);
#endif
#ifdef ICMP6_DST_UNREACH_BEYONDSCOPE
    PyModule_AddIntConstant(
	m, "ICMP6_DST_UNREACH_BEYONDSCOPE", ICMP6_DST_UNREACH_BEYONDSCOPE);
#else
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH_BEYONDSCOPE", 2);
#endif
#ifdef ICMP6_DST_UNREACH_NOPORT
    PyModule_AddIntConstant(
	m, "ICMP6_DST_UNREACH_NOPORT", ICMP6_DST_UNREACH_NOPORT);
#else
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH_NOPORT", 4);
#endif
#ifdef ICMP6_DST_UNREACH_NOROUTE
    PyModule_AddIntConstant(
	m, "ICMP6_DST_UNREACH_NOROUTE", ICMP6_DST_UNREACH_NOROUTE);
#else
    PyModule_AddIntConstant(m, "ICMP6_DST_UNREACH_NOROUTE", 0);
#endif
#ifdef ICMP6_ECHO_REPLY
    PyModule_AddIntConstant(m, "ICMP6_ECHO_REPLY", ICMP6_ECHO_REPLY);
#else
    PyModule_AddIntConstant(m, "ICMP6_ECHO_REPLY", 129);
#endif
#ifdef ICMP6_ECHO_REQUEST
    PyModule_AddIntConstant(m, "ICMP6_ECHO_REQUEST", ICMP6_ECHO_REQUEST);
#else
    PyModule_AddIntConstant(m, "ICMP6_ECHO_REQUEST", 128);
#endif
#ifdef ICMP6_INFOMSG_MASK
    PyModule_AddIntConstant(m, "ICMP6_INFOMSG_MASK", ICMP6_INFOMSG_MASK);
#else
    PyModule_AddIntConstant(m, "ICMP6_INFOMSG_MASK", 0x80);
#endif
#ifdef ICMP6_PACKET_TOO_BIG
    PyModule_AddIntConstant(m, "ICMP6_PACKET_TOO_BIG", ICMP6_PACKET_TOO_BIG);
#else
    PyModule_AddIntConstant(m, "ICMP6_PACKET_TOO_BIG", 2);
#endif
#ifdef ICMP6_PARAMPROB_HEADER
    PyModule_AddIntConstant(
	m, "ICMP6_PARAMPROB_HEADER", ICMP6_PARAMPROB_HEADER);
#else
    PyModule_AddIntConstant(m, "ICMP6_PARAMPROB_HEADER", 0);
#endif
#ifdef ICMP6_PARAMPROB_NEXTHEADER
    PyModule_AddIntConstant(
	m, "ICMP6_PARAMPROB_NEXTHEADER", ICMP6_PARAMPROB_NEXTHEADER);
#else
    PyModule_AddIntConstant(m, "ICMP6_PARAMPROB_NEXTHEADER", 1);
#endif
#ifdef ICMP6_PARAMPROB_OPTION
    PyModule_AddIntConstant(
	m, "ICMP6_PARAMPROB_OPTION", ICMP6_PARAMPROB_OPTION);
#else
    PyModule_AddIntConstant(m, "ICMP6_PARAMPROB_OPTION", 2);
#endif
#ifdef ICMP6_PARAM_PROB
    PyModule_AddIntConstant(m, "ICMP6_PARAM_PROB", ICMP6_PARAM_PROB);
#else
    PyModule_AddIntConstant(m, "ICMP6_PARAM_PROB", 4);
#endif
#ifdef ICMP6_ROUTER_RENUMBERING
    PyModule_AddIntConstant(
	m, "ICMP6_ROUTER_RENUMBERING", ICMP6_ROUTER_RENUMBERING);
#else
    PyModule_AddIntConstant(m, "ICMP6_ROUTER_RENUMBERING", 136);
#endif
#ifdef ICMP6_RR_FLAGS_FORCEAPPLY
    PyModule_AddIntConstant(
	m, "ICMP6_RR_FLAGS_FORCEAPPLY", ICMP6_RR_FLAGS_FORCEAPPLY);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_FLAGS_FORCEAPPLY", 0x20);
#endif
#ifdef ICMP6_RR_FLAGS_PREVDONE
    PyModule_AddIntConstant(
	m, "ICMP6_RR_FLAGS_PREVDONE", ICMP6_RR_FLAGS_PREVDONE);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_FLAGS_PREVDONE", 0x08);
#endif
#ifdef ICMP6_RR_FLAGS_REQRESULT
    PyModule_AddIntConstant(
	m, "ICMP6_RR_FLAGS_REQRESULT", ICMP6_RR_FLAGS_REQRESULT);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_FLAGS_REQRESULT", 0x40);
#endif
#ifdef ICMP6_RR_FLAGS_SPECSITE
    PyModule_AddIntConstant(
	m, "ICMP6_RR_FLAGS_SPECSITE", ICMP6_RR_FLAGS_SPECSITE);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_FLAGS_SPECSITE", 0x10);
#endif
#ifdef ICMP6_RR_FLAGS_TEST
    PyModule_AddIntConstant(m, "ICMP6_RR_FLAGS_TEST", ICMP6_RR_FLAGS_TEST);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_FLAGS_TEST", 0x80);
#endif
#ifdef ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME",
			    ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME", 0x40000000);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME", 0x40);
#endif
#endif
#ifdef ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME",
			    ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME", 0x80000000);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME", 0x80);
#endif
#endif
#ifdef ICMP6_RR_PCOUSE_RAFLAGS_AUTO
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_RAFLAGS_AUTO",
			    ICMP6_RR_PCOUSE_RAFLAGS_AUTO);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_RAFLAGS_AUTO", 0x10);
#endif
#ifdef ICMP6_RR_PCOUSE_RAFLAGS_ONLINK
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_RAFLAGS_ONLINK",
			    ICMP6_RR_PCOUSE_RAFLAGS_ONLINK);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_PCOUSE_RAFLAGS_ONLINK", 0x20);
#endif
#ifdef ICMP6_RR_RESULT_FLAGS_FORBIDDEN
    PyModule_AddIntConstant(
	m, "ICMP6_RR_RESULT_FLAGS_FORBIDDEN", ICMP6_RR_RESULT_FLAGS_FORBIDDEN);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ICMP6_RR_RESULT_FLAGS_FORBIDDEN", 0x0001);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_RESULT_FLAGS_FORBIDDEN", 0x0100);
#endif
#endif
#ifdef ICMP6_RR_RESULT_FLAGS_OOB
    PyModule_AddIntConstant(
	m, "ICMP6_RR_RESULT_FLAGS_OOB", ICMP6_RR_RESULT_FLAGS_OOB);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ICMP6_RR_RESULT_FLAGS_OOB", 0x0002);
#else
    PyModule_AddIntConstant(m, "ICMP6_RR_RESULT_FLAGS_OOB", 0x0200);
#endif
#endif
#ifdef ICMP6_TIME_EXCEEDED
    PyModule_AddIntConstant(m, "ICMP6_TIME_EXCEEDED", ICMP6_TIME_EXCEEDED);
#else
    PyModule_AddIntConstant(m, "ICMP6_TIME_EXCEEDED", 3);
#endif
#ifdef ICMP6_TIME_EXCEED_REASSEMBLY
    PyModule_AddIntConstant(
	m, "ICMP6_TIME_EXCEED_REASSEMBLY", ICMP6_TIME_EXCEED_REASSEMBLY);
#else
    PyModule_AddIntConstant(m, "ICMP6_TIME_EXCEED_REASSEMBLY", 1);
#endif
#ifdef ICMP6_TIME_EXCEED_TRANSIT
    PyModule_AddIntConstant(
	m, "ICMP6_TIME_EXCEED_TRANSIT", ICMP6_TIME_EXCEED_TRANSIT);
#else
    PyModule_AddIntConstant(m, "ICMP6_TIME_EXCEED_TRANSIT", 0);
#endif
#ifdef MLD_LISTENER_QUERY
    PyModule_AddIntConstant(m, "MLD_LISTENER_QUERY", MLD_LISTENER_QUERY);
#else
    PyModule_AddIntConstant(m, "MLD_LISTENER_QUERY", 130);
#endif
#ifdef MLD_LISTENER_REDUCTION
    PyModule_AddIntConstant(
	m, "MLD_LISTENER_REDUCTION", MLD_LISTENER_REDUCTION);
#else
    PyModule_AddIntConstant(m, "MLD_LISTENER_REDUCTION", 132);
#endif
#ifdef MLD_LISTENER_REPORT
    PyModule_AddIntConstant(m, "MLD_LISTENER_REPORT", MLD_LISTENER_REPORT);
#else
    PyModule_AddIntConstant(m, "MLD_LISTENER_REPORT", 131);
#endif
#ifdef ND_NA_FLAG_OVERRIDE
    PyModule_AddIntConstant(m, "ND_NA_FLAG_OVERRIDE", ND_NA_FLAG_OVERRIDE);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ND_NA_FLAG_OVERRIDE", 0x20000000);
#else
	PyModule_AddIntConstant(m, "ND_NA_FLAG_OVERRIDE", 0x00000020);
#endif
#endif
#ifdef ND_NA_FLAG_ROUTER
    PyModule_AddIntConstant(m, "ND_NA_FLAG_ROUTER", ND_NA_FLAG_ROUTER);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ND_NA_FLAG_ROUTER", 0x80000000);
#else
    PyModule_AddIntConstant(m, "ND_NA_FLAG_ROUTER", 0x00000080);
#endif
#endif
#ifdef ND_NA_FLAG_SOLICITED
    PyModule_AddIntConstant(m, "ND_NA_FLAG_SOLICITED", ND_NA_FLAG_SOLICITED);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "ND_NA_FLAG_SOLICITED", 0x40000000);
#else
    PyModule_AddIntConstant(m, "ND_NA_FLAG_SOLICITED", 0x00000040);
#endif
#endif
#ifdef ND_NEIGHBOR_ADVERT
    PyModule_AddIntConstant(m, "ND_NEIGHBOR_ADVERT", ND_NEIGHBOR_ADVERT);
#else
    PyModule_AddIntConstant(m, "ND_NEIGHBOR_ADVERT", 136);
#endif
#ifdef ND_NEIGHBOR_SOLICIT
    PyModule_AddIntConstant(m, "ND_NEIGHBOR_SOLICIT", ND_NEIGHBOR_SOLICIT);
#else
    PyModule_AddIntConstant(m, "ND_NEIGHBOR_SOLICIT", 135);
#endif
#ifdef ND_OPT_MTU
    PyModule_AddIntConstant(m, "ND_OPT_MTU", ND_OPT_MTU);
#else
    PyModule_AddIntConstant(m, "ND_OPT_MTU", 5);
#endif
#ifdef ND_OPT_PI_FLAG_AUTO
    PyModule_AddIntConstant(m, "ND_OPT_PI_FLAG_AUTO", ND_OPT_PI_FLAG_AUTO);
#else
    PyModule_AddIntConstant(m, "ND_OPT_PI_FLAG_AUTO", 0x40);
#endif
#ifdef ND_OPT_PI_FLAG_ONLINK
    PyModule_AddIntConstant(m, "ND_OPT_PI_FLAG_ONLINK", ND_OPT_PI_FLAG_ONLINK);
#else
    PyModule_AddIntConstant(m, "ND_OPT_PI_FLAG_ONLINK", 0x80);
#endif
#ifdef ND_OPT_PREFIX_INFORMATION
    PyModule_AddIntConstant(
	m, "ND_OPT_PREFIX_INFORMATION", ND_OPT_PREFIX_INFORMATION);
#else
    PyModule_AddIntConstant(m, "ND_OPT_PREFIX_INFORMATION", 3);
#endif
#ifdef ND_OPT_REDIRECTED_HEADER
    PyModule_AddIntConstant(
	m, "ND_OPT_REDIRECTED_HEADER", ND_OPT_REDIRECTED_HEADER);
#else
    PyModule_AddIntConstant(m, "ND_OPT_REDIRECTED_HEADER", 4);
#endif
#ifdef ND_OPT_SOURCE_LINKADDR
    PyModule_AddIntConstant(
	m, "ND_OPT_SOURCE_LINKADDR", ND_OPT_SOURCE_LINKADDR);
#else
    PyModule_AddIntConstant(m, "ND_OPT_SOURCE_LINKADDR", 1);
#endif
#ifdef ND_OPT_TARGET_LINKADDR
    PyModule_AddIntConstant(
	m, "ND_OPT_TARGET_LINKADDR", ND_OPT_TARGET_LINKADDR);
#else
    PyModule_AddIntConstant(m, "ND_OPT_TARGET_LINKADDR", 2);
#endif
#ifdef ND_RA_FLAG_MANAGED
    PyModule_AddIntConstant(m, "ND_RA_FLAG_MANAGED", ND_RA_FLAG_MANAGED);
#else
    PyModule_AddIntConstant(m, "ND_RA_FLAG_MANAGED", 0x80);
#endif
#ifdef ND_RA_FLAG_OTHER
    PyModule_AddIntConstant(m, "ND_RA_FLAG_OTHER", ND_RA_FLAG_OTHER);
#else
    PyModule_AddIntConstant(m, "ND_RA_FLAG_OTHER", 0x40);
#endif
#ifdef ND_REDIRECT
    PyModule_AddIntConstant(m, "ND_REDIRECT", ND_REDIRECT);
#else
    PyModule_AddIntConstant(m, "ND_REDIRECT", 137);
#endif
#ifdef ND_ROUTER_ADVERT
    PyModule_AddIntConstant(m, "ND_ROUTER_ADVERT", ND_ROUTER_ADVERT);
#else
    PyModule_AddIntConstant(m, "ND_ROUTER_ADVERT", 134);
#endif
#ifdef ND_ROUTER_SOLICIT
    PyModule_AddIntConstant(m, "ND_ROUTER_SOLICIT", ND_ROUTER_SOLICIT);
#else
    PyModule_AddIntConstant(m, "ND_ROUTER_SOLICIT", 133);
#endif

/* Constants in <netinet/ip6.h> */
#ifdef IP6F_MORE_FRAG
    PyModule_AddIntConstant(m, "IP6F_MORE_FRAG", IP6F_MORE_FRAG);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "IP6F_MORE_FRAG", 0x0001);
#else
    PyModule_AddIntConstant(m, "IP6F_MORE_FRAG", 0x0100);
#endif
#endif
#ifdef IP6F_OFF_MASK
    PyModule_AddIntConstant(m, "IP6F_OFF_MASK", IP6F_OFF_MASK);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "IP6F_OFF_MASK", 0xfff8);
#else
    PyModule_AddIntConstant(m, "IP6F_OFF_MASK", 0xf8ff);
#endif
#endif
#ifdef IP6F_RESERVED_MASK
    PyModule_AddIntConstant(m, "IP6F_RESERVED_MASK", IP6F_RESERVED_MASK);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "IP6F_RESERVED_MASK", 0x0006);
#else
    PyModule_AddIntConstant(m, "IP6F_RESERVED_MASK", 0x0600);
#endif
#endif
#ifdef IP6OPT_JUMBO
    PyModule_AddIntConstant(m, "IP6OPT_JUMBO", IP6OPT_JUMBO);
#else
    PyModule_AddIntConstant(m, "IP6OPT_JUMBO", 0xc2);
#endif
#ifdef IP6OPT_JUMBO_LEN
    PyModule_AddIntConstant(m, "IP6OPT_JUMBO_LEN", IP6OPT_JUMBO_LEN);
#else
    PyModule_AddIntConstant(m, "IP6OPT_JUMBO_LEN", 6);
#endif
#ifdef IP6OPT_MUTABLE
    PyModule_AddIntConstant(m, "IP6OPT_MUTABLE", IP6OPT_MUTABLE);
#else
    PyModule_AddIntConstant(m, "IP6OPT_MUTABLE", 0x20);
#endif
#ifdef IP6OPT_NSAP_ADDR
    PyModule_AddIntConstant(m, "IP6OPT_NSAP_ADDR", IP6OPT_NSAP_ADDR);
#else
    PyModule_AddIntConstant(m, "IP6OPT_NSAP_ADDR", 0xc3);
#endif
#ifdef IP6OPT_PAD1
    PyModule_AddIntConstant(m, "IP6OPT_PAD1", IP6OPT_PAD1);
#else
    PyModule_AddIntConstant(m, "IP6OPT_PAD1", 0x00);
#endif
#ifdef IP6OPT_PADN
    PyModule_AddIntConstant(m, "IP6OPT_PADN", IP6OPT_PADN);
#else
    PyModule_AddIntConstant(m, "IP6OPT_PADN", 0x01);
#endif
#ifdef IP6OPT_ROUTER_ALERT
    PyModule_AddIntConstant(m, "IP6OPT_ROUTER_ALERT", IP6OPT_ROUTER_ALERT);
#else
    PyModule_AddIntConstant(m, "IP6OPT_ROUTER_ALERT", 0x05);
#endif
#ifdef IP6OPT_TUNNEL_LIMIT
    PyModule_AddIntConstant(m, "IP6OPT_TUNNEL_LIMIT", IP6OPT_TUNNEL_LIMIT);
#else
    PyModule_AddIntConstant(m, "IP6OPT_TUNNEL_LIMIT", 0x04);
#endif
#ifdef IP6OPT_TYPE_DISCARD
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_DISCARD", IP6OPT_TYPE_DISCARD);
#else
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_DISCARD", 0x40);
#endif
#ifdef IP6OPT_TYPE_FORCEICMP
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_FORCEICMP", IP6OPT_TYPE_FORCEICMP);
#else
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_FORCEICMP", 0x80);
#endif
#ifdef IP6OPT_TYPE_ICMP
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_ICMP", IP6OPT_TYPE_ICMP);
#else
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_ICMP", 0xc0);
#endif
#ifdef IP6OPT_TYPE_SKIP
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_SKIP", IP6OPT_TYPE_SKIP);
#else
    PyModule_AddIntConstant(m, "IP6OPT_TYPE_SKIP", 0x00);
#endif
#ifdef IP6_ALERT_AN
    PyModule_AddIntConstant(m, "IP6_ALERT_AN", IP6_ALERT_AN);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "IP6_ALERT_AN", 0x0002);
#else
    PyModule_AddIntConstant(m, "IP6_ALERT_AN", 0x0200);
#endif
#endif
#ifdef IP6_ALERT_MLD
    PyModule_AddIntConstant(m, "IP6_ALERT_MLD", IP6_ALERT_MLD);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "IP6_ALERT_MLD", 0x0000);
#else
    PyModule_AddIntConstant(m, "IP6_ALERT_MLD", 0x0000);
#endif
#endif
#ifdef IP6_ALERT_RSVP
    PyModule_AddIntConstant(m, "IP6_ALERT_RSVP", IP6_ALERT_RSVP);
#else
#ifdef WORDS_BIGENDIAN
    PyModule_AddIntConstant(m, "IP6_ALERT_RSVP", 0x0001);
#else
    PyModule_AddIntConstant(m, "IP6_ALERT_RSVP", 0x0100);
#endif
#endif
}

/*****************************************************************************
 * LOCAL FUNCTION DEFINITIONS
 *****************************************************************************/

#ifdef IPV6_RTHDR
#ifndef HAVE_INET6_RTH_SPACE
static socklen_t
inet6_rth_space(int type, int segments)
{
    switch (type) {
    case IPV6_RTHDR_TYPE_0:
	if (segments < 0 || segments > 127)
	    return 0;
	return (((segments * 2) + 1) << 3);
    default:
	return 0;
    }
}
#endif

#ifndef HAVE_INET6_RTH_INIT
static void *
inet6_rth_init(void *bp, socklen_t bp_len, int type, int segments)
{
    switch (type) {
    case IPV6_RTHDR_TYPE_0:
    {
	struct ip6_rthdr0 *rth0 = (struct ip6_rthdr0 *) bp;

	if (bp_len < inet6_rth_space(IPV6_RTHDR_TYPE_0, segments))
	    return NULL;
	memset((void *) bp, 0, bp_len);
	rth0->ip6r0_len = segments * 2;
	rth0->ip6r0_type = IPV6_RTHDR_TYPE_0;
	break;
    }
    default:
	return NULL;
    }
    return bp;
}
#endif

#ifndef HAVE_INET6_RTH_ADD
static int
inet6_rth_add(void *bp, const struct in6_addr *addr)
{
    struct ip6_rthdr *rth = (struct ip6_rthdr *) bp;

    switch (rth->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
    {
	struct ip6_rthdr0 *rth0 = (struct ip6_rthdr0 *) rth;
	struct in6_addr *ap =
	    (struct in6_addr *) ((char *) bp + 8) + rth0->ip6r0_segleft;

	memcpy((void *) ap, (void *) addr, sizeof(struct in6_addr));
	rth0->ip6r0_segleft++;
	break;
    }
    default:
	return -1;
    }
    return 0;
}
#endif

#ifndef HAVE_INET6_RTH_SEGMENTS
static int
inet6_rth_segments(const void *bp)
{
    int nb;
    struct ip6_rthdr *rth = (struct ip6_rthdr *) bp;
    
    switch (rth->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
    {
	struct ip6_rthdr0 *rth0 = (struct ip6_rthdr0 *) rth;
	
	if (rth0->ip6r0_len % 2)
	    return -1;
	nb = rth0->ip6r0_len >> 1;
	if (nb < rth0->ip6r0_segleft)
	    return -1;
	return nb;
    }
    default:
	return -1;
    }
}
#endif

#ifndef HAVE_INET6_RTH_REVERSE
static int
inet6_rth_reverse(const void *in, void *out)
{
    struct ip6_rthdr *rth = (struct ip6_rthdr *) in;
    
    switch (rth->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
    {
	int i, segments;
	struct ip6_rthdr0 *rth0_in = (struct ip6_rthdr0 *) in;
	struct ip6_rthdr0 *rth0_out = (struct ip6_rthdr0 *) out;
	
	if (rth0_in->ip6r0_len % 2)
	    return -1;
	segments = rth0_in->ip6r0_len >> 1;
	memmove((void *) rth0_out, (void *) rth0_in,
		(rth0_in->ip6r0_len + 1) << 3);
	rth0_out->ip6r0_segleft = segments;
	for (i = 0; i < segments >> 1; i++) {
	    struct in6_addr at, *ap1, *ap2;

	    ap1 = (struct in6_addr *) ((char *) out + 8) + i;
	    ap2 = (struct in6_addr *) ((char *) out + 8) + segments - i - 1;
	    memcpy((void *) &at, (void *) ap1, sizeof(struct in6_addr));
	    memcpy((void *) ap1, (void *) ap2, sizeof(struct in6_addr));
	    memcpy((void *) ap2, (void *) &at, sizeof(struct in6_addr));
	}
	return 0;
    }
    default:
	return -1;
    }
}
#endif

#ifndef HAVE_INET6_RTH_GETADDR
struct in6_addr *
inet6_rth_getaddr(const void *bp, int idx)
{
    int nb;
    struct ip6_rthdr *rth = (struct ip6_rthdr *) bp;
    
    switch (rth->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
    {
	struct ip6_rthdr0 *rth0 = (struct ip6_rthdr0 *) rth;
	
	if (rth0->ip6r0_len % 2)
	    return NULL;
	nb = rth0->ip6r0_len >> 1;
	if (nb < rth0->ip6r0_segleft)
	    return NULL;
	if (idx < 0 || idx >= nb)
	    return NULL;
	return (struct in6_addr *) ((char *) bp + 8) + idx;
    }
    default:
	return NULL;
    }
}
#endif
#endif /* IPV6_RTHDR */

/* 
 * inet6_opt_* routines are adapted from KAME IPv6 stack :
 * $KAME: ip6opt.c,v 1.15 2004/06/01 12:59:33 jinmei Exp $
 */

#if defined(IPV6_HOPOPTS) || defined(IPV6_DSTOPTS) || \
    defined(IPV6_RTHDRDSTOPTS)
#ifndef IP6OPT_PAD1
#define IP6OPT_PAD1 0x00
#endif
#ifndef IP6OPT_PADN
#define IP6OPT_PADN 0x01
#endif

#if !defined(HAVE_INET6_OPT_NEXT) || !defined(HAVE_INET6_OPT_FIND)
static int
ip6optlen(uint8_t *opt, uint8_t *lim)
{
    int optlen;
    
    if (*opt == IP6OPT_PAD1)
	optlen = 1;
    else {
	if (opt + 2 > lim)
	    return 0;
	optlen = *(opt + 1) + 2;
    }
    if (opt + optlen <= lim)
	return optlen;
    return 0;
}
#endif

#ifndef HAVE_INET6_OPT_INIT
static int
inet6_opt_init(void *extbuf, socklen_t extlen)
{
    struct ip6_opt *opt = (struct ip6_opt *) extbuf;

    if (opt != NULL) {
	if (extlen <= 0 || extlen % 8)
	    return -1;
	opt->ip6o_len = (extlen >> 3) - 1;
    }
    return 2;
}
#endif

#ifndef HAVE_INET6_OPT_APPEND
static int
inet6_opt_append(void *extbuf, socklen_t extlen, int offset, uint8_t type,
		 socklen_t len, uint8_t align, void **databufp)
{
    int curlen = offset, padlen = 0;
    
    if (type < 2)
	return -1;
    if (len < 0 || len > 255)
	return -1;
    if (align != 1 && align != 2 && align != 4 && align != 8)
	return -1;
    if (align > len)
	return -1;
    curlen += 2 + len;
    if (curlen % align)
	padlen = align - (curlen % align);
    curlen += padlen;
    if (extlen && curlen > extlen)
	return -1;
    if (extbuf != NULL) {
	uint8_t *optp = (uint8_t *) extbuf + offset;
	
	if (padlen == 1) {
	    *optp = IP6OPT_PAD1;
	    optp++;
	}
	else
	    if (padlen > 0) {
		*optp++ = IP6OPT_PADN;
		*optp++ = padlen - 2;
		memset((void *) optp, 0, padlen - 2);
		optp += padlen - 2;
	    }
	*optp++ = type;
	*optp++ = len;
	*databufp = (void *) optp;
    }
    return curlen;
}
#endif

#ifndef HAVE_INET6_OPT_FINISH
static int
inet6_opt_finish(void *extbuf, socklen_t extlen, int offset)
{
    int utl = offset > 0 ? (1 + ((offset - 1) | 7)) : 0;
    
    if (extbuf) {
	uint8_t *padp;
	int padlen = utl - offset;
	
	if (utl > extlen)
	    return -1;
	padp = (uint8_t *) extbuf + offset;
	if (padlen == 1)
	    *padp = IP6OPT_PAD1;
	else if (padlen > 0) {
	    *padp++ = IP6OPT_PADN;
	    *padp++ = (padlen - 2);
	    memset((void *) padp, 0, padlen - 2);
	}
    }
    return utl;
}
#endif

#ifndef HAVE_INET6_OPT_SET_VAL
static int
inet6_opt_set_val(void *databuf, int offset, void *val, socklen_t vallen)
{
    memcpy((void *) ((uint8_t *) databuf + offset), val, vallen);
    return offset + vallen;
}
#endif

#ifndef HAVE_INET6_OPT_NEXT
static int
inet6_opt_next(void *extbuf, socklen_t extlen, int offset, uint8_t *typep,
	       socklen_t *lenp, void **databufp)
{
    uint8_t *optp, *lim;
    int optlen;
    
    if (extlen == 0 || extlen % 8)
	return -1;
    lim = (uint8_t *) extbuf + extlen;
    if (offset == 0)
	optp = (uint8_t *) (extbuf + 2);
    else
	optp = (uint8_t *) extbuf + offset;
    while(optp < lim)
	switch(*optp) {
	case IP6OPT_PAD1:
	    optp++;
	    break;
	case IP6OPT_PADN:
	    if ((optlen = ip6optlen(optp, lim)) == 0)
		goto optend;
	    optp += optlen;
	    break;
	default:
	    if ((optlen = ip6optlen(optp, lim)) == 0)
		goto optend;
	    *typep = *optp;
	    *lenp = optlen - 2;
	    *databufp = (void *) (optp + 2);
	    return optp + optlen - (uint8_t *) extbuf;
	}
  optend:
    *databufp = NULL;
    return -1;
}
#endif

#ifndef HAVE_INET6_OPT_FIND
static int
inet6_opt_find(void *extbuf, socklen_t extlen, int offset, uint8_t type,
	       socklen_t *lenp, void **databufp)
{
    uint8_t *optp, *lim;
    int optlen;
    
    if (extlen == 0 || extlen % 8)
	return -1;
    lim = (uint8_t *) extbuf + extlen;
    if (offset == 0)
	optp = (uint8_t *) (extbuf + 2);
    else
	optp = (uint8_t *) extbuf + offset;
    while(optp < lim) {
	if ((optlen = ip6optlen(optp, lim)) == 0)
	    goto optend;
	if (*optp == type) {
	    *lenp = optlen - 2;
	    *databufp = (void *) (optp + 2);
	    return optp + optlen - (uint8_t *) extbuf;
	}
	optp += optlen;
    }
  optend:
    *databufp = NULL;
    return -1;
}
#endif

#ifndef HAVE_INET6_OPT_GET_VAL
static int
inet6_opt_get_val(void *databuf, int offset, void *val, socklen_t vallen)
{
    memcpy(val, (void *) ((uint8_t *) databuf + offset), vallen);
    return offset + vallen;
}
#endif
#endif /* IPV6_HOPOPTS, ... */
