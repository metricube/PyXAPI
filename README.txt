This is PyXAPI version 0.1
==========================

PyXAPI package consists of two modules: `socket_ext' and `rfc3542'. The
second one is optional (see file INSTALL.txt for more details).

  1. `socket_ext' extends the Python module `socket'. `socket' objects have
     two new methods: `recvmsg' and `sendmsg'. It defines `ancillary data'
     objects and some functions related to. `socket_ext' module also provides
     functions to manage interfaces indexes defined in RFC3494 and not
     available from standard Python module `socket'.

  2. `rfc3542' is a full implementation of RFC3542 (Advanced Sockets
     Application Program Interface (API) for IPv6).

License information
===================

PyXAPI is free software. See the file COPYING for copying conditions.

Requirements
============

See file INSTALL.txt.

The `socket_ext' module
=======================

Introduction
------------

`socket_ext', is an extension of Python module `socket'. It adds two
methods to the standard Python socket object: `recvmsg' and `sendmsg' which
are wrappers for the well known UNIX system calls `recvmsg' and `sendmsg'
respectively. As a first example, let us show how to send data via a TCP
connected socket:

from socket_ext import *
s = socket(AF_INET, SOCK_STREAM)
s.connect((host, port))
s.sendmsg(('This is a test',))

which is equivalent to:

from socket import *
s = socket(AF_INET, SOCK_STREAM)
s.connect((host, port))
s.send('This is a test')

Note that first argument of `sendmsg' is a tuple of string. It is the
scatter/gather array passed to the UNIX system call `sendmsg' (see UNIX
manual for more details). We could also have done:

s.sendmsg(('This is ', 'a test'))

Now to receive data (`s' same as above):

addr, data, adata, flags = s.recvmsg((14,))

Argument of method `recvmsg' is a tuple of integers. Each integer is the
size of the corresponding element of the scatter/gather array passed to
the UNIX system call `recvmsg'.
`addr' is the destination address as a Python socket (IPv4) address, i.e
a 2-tuple `(host, port)'.
`data' is a tuple of strings. Suppose we have received the following data:
`'This is a test'', then `data' is the tuple `('This is a test',)'.
If we did:

addr, data, adata, flags = s.recvmsg((12, 2))

`data' would be the tuple `('This is a te', 'st')'
`adata' is a tuple of ancillary data (see below). In this example, there
are no ancillary data, so `adata' is the empty tuple.
Finally `flags' is flags on received message. It is usually used to do error
checking as follows:

if flags & MSG_TRUNC:
   print 'data are truncated'
if flags & MSG_CTRUNC:
   print 'ancillary data are truncated'

Ancillary data
--------------

  `socket_ext' module defines a new object (of type CMSGType) to handle
ancillary data. To create such an object:

from socket_ext import *
c = cmsg()

An ancillary data object has four methods: `set', `set_from_data', `get'
and `CMSG_DATA'. For example, if you want to build a ancillary data object
with `IP_TTL' option, you should proceed as follows:

import struct
from socket_ext import *
ttl = struct.pack('L', 1)
c = cmsg()
c.set(SOL_IP, IP_TTL, ttl)

First argument of method `set' is the originating protocol, second argument
is the protocol-specific type and last argument is the raw data as a Python
string.

If you want to access to ancillary data fields, use method `get':

>>> print c.get()
((16, 0, 4), '\x01\x00\x00\x00')

If you just want to get data:

>>> print '%r' % c.CMSG_DATA()
'\x01\x00\x00\x00'

or in a more realistic way:

ttl = struct.unpack('L',  c.CMSG_DATA())[0]

The last method, `set_from_data' is used when you have to initialize a
ancillary data from raw data (Python string). This method is not really
needed because socket method `recvmsg' does all the job for you (see below).
Ancillary data objects have also four attributes:

>>> print c.cmsg_len, c.cmsg_level, c.cmsg_type, '%r' % c.cmsg_data
16 0 4 '\x01\x00\x00\x00'

Note: `c.cmsg_data' is strictly equivalent to `c.CMSG_DATA()'.

  `socket_ext' module defines also two methods which are wrappers for macros
`CMSG_SPACE' and `CMSG_LEN' (refer to UNIX manual for a full explanation):

>>> print CMSG_SPACE(struct.calcsize('L')), CMSG_LEN(struct.calcsize('L'))
16 16

It is now easy to send data with ancillary data `c':

s = socket(AF_INET, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (c,))

You can notice that ancillary data (third argument) is a tuple. It is because
it is possible to send several ancillary data simultaneously. We need also to
give destination address (first argument) because `s' is an unconnected socket.
  Processing ancillary data received is no more difficult:

alen =  CMSG_SPACE(struct.calcsize('L'))
addr, data, adata, flags = s.recvmsg((1024,), alen)
for a in adata:
    if a.cmsg_level == SOL_IP and a.cmsg_type == IP_TTL:
        print 'TTL: %u' % struct.unpack('L',  c.cmsg_data)[0]

The second parameter of `recvmsg' method is the length of the buffer which
contains received ancillary data. We expect an integer, so data part of
ancillary data has size equal to `struct.calcsize('L')'. We then use macro
`CMSG_SPACE' to calculate ancillary data size (see UNIX manual for a full
description of this macro).

Interface methods:
------------------

While RFC3493 (Basic Socket Interface Extensions for IPv6) defines some
functions to manage interfaces indexes, standard Python socket module
does not provide them (they are useful in `rfc3542' module). They have been
added in `socket_ext' module:

>>> print if_nametoindex('fxp0')
1
>>> print if_indextoname(3)
gif0
>>> print if_nameindex()
[(1, 'fxp0'), (2, 'lp0'), (3, 'gif0'), (4, 'lo0'), (5, 'ppp0'), (6, 'sl0')]

Please refer to  RFC3493, section 4 (Interface Identification) for a full
description of these functions.

The `rfc3542' module
====================

Introduction
------------

  This module is a full implementation of RFC3542 (Advanced Sockets
Application Program Interface (API) for IPv6) and (in general) needs
`socket_ext module previously described; every program calling this module
should contain the following lines:

from socket_ext import *
from rfc3542 import *

You must have Python socket module compiled with IPv6 support (see file
INSTALL.txt) if you plan to use this (optional) module.
  Of course, we shall not explain or comment RFC3542. Reader is strongly
encouraged to read this document BEFORE going further.
  For each option, `rfc3542' module defines an appropriate new object. Each
object (`icmp6_filter' excepted) has three methods: `set', `set_from_data'
and `get'. Every object has a `data' attribute which is the object as a (raw)
Python string). This attribute is in particular used when passing an object
to `set/getsockopt' methods (see below).

`icmp6_filter' objects
----------------------

  When an ICMPv6 raw socket is created, it will by default pass all ICMPv6
message types to the application. If an application wants only receive
ICMPv6 Echo Reply:

f = icmp6_filter() # object is created
f.ICMP6_FILTER_SETBLOCKALL();
f.ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY);
s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)
s.setsockopt(IPPROTO_ICMPV6, ICMP6_FILTER, f.data)

`hoplimit' objects
------------------

  To specify hop limit as ancillary data, you can proceed like that:

h = hoplimit() # object is created
h.set(16) # setting hop limit to 16
c = cmsg()
c.set(IPPROTO_IPV6, IPV6_HOPLIMIT, h.data)
s = socket(AF_INET6, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (c,))

To receive hop limit as ancillary data, you must enable IPV6_RECVHOPLIMIT
socket option:

s.setsockopt(IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)

and proceed as follows:

h = hoplimit()
alen = CMSG_SPACE(h.size) # computing ancillary data size, see below
addr, data, adata, flags = s.recvmsg((1024,), alen)
for a in adata:
    if a.cmsg_level == IPPROTO_IPV6 and a.cmsg_type == IPV6_HOPLIMIT:
        h.set_from_data(a.cmsg_data)
        print 'hop limit: %u' % h.get()

To help programmer to compute ancillary data size, each object (except
`inet6_rth objects, see below) has a `size' attribute. This attribute
is the size in bytes of the option (not object) and is usually passed
to CMSG_SPACE macro.

`tclass' objects
----------------

  To specify traffic class as ancillary data, you can proceed like that:

h = tclass() # object is created
h.set(0x08)
c = cmsg()
c.set(IPPROTO_IPV6, IPV6_TCLASS, h.data)
s = socket(AF_INET6, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (c,))

To receive traffic class as ancillary data, you must enable IPV6_RECVTCLASS
socket option:

s.setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 1)

and proceed as follows:

t = tclass()
alen = CMSG_SPACE(t.size)
addr, data, adata, flags = s.recvmsg((1024,), alen)
for a in adata:
    if a.cmsg_level == IPPROTO_IPV6 and a.cmsg_type == IPV6_TCLASS:
        t.set_from_data(a.cmsg_data)
        print 'traffic class: 0x%.2x' % t.get()

Note: option `IPV6_TCLASS' is not implemented on all Linux platforms.

`in6_pktinfo' objects
---------------------

  To specify pktinfo as ancillary data, you can proceed like that:

p = in6_pktinfo() # object is created
p.set('::', if_nametoindex('eth0')) # (unspecified address, interface eth0)
c = cmsg()
c.set(IPPROTO_IPV6, IPV6_PKTINFO, p.data)
s = socket(AF_INET6, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (c,))

To receive in6_pktinfo as ancillary data, you must enable IPV6_RECVPKTINFO
socket option:

s.setsockopt(IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)

and proceed as follows:

p = in6_pktinfo()
alen = CMSG_SPACE(p.size)
addr, data, adata, flags = s.recvmsg((1024,), alen)
for a in adata:
    if a.cmsg_level == IPPROTO_IPV6 and a.cmsg_type == IPV6_PKTINFO:
        p.set_from_data(a.cmsg_data)
	p = p.get()
        print "pktinfo: addr='%s', if=%s" % (p[0], if_indextoname(p[1]))

`nexthop' objects
-----------------

  To specify nexthop as ancillary data, you can proceed like that:

p = nexthop() # object is created
p.set('3ffe::1') # setting the next hop address
c = cmsg()
c.set(IPPROTO_IPV6, IPV6_NEXTHOP, p.data)
s = socket(AF_INET6, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (c,))

Note: this is a privileged option. This option does not have any meaning for
multicast destinations.

`inet6_rth' objects
-------------------

  To specify routing header (of type 0 (`IPV6_RTHDR_TYPE_0')) as ancillary
data, you can proceed like that:

r = inet6_rth() # object is created
r = inet6_rth_init(r, IPV6_RTHDR_TYPE_0, 2) # initialization (2 nodes)
inet6_rth_add(r, '3ffe::1') # adding first intermediate node
inet6_rth_add(r, '3ffe::2') # adding second intermediate node

The four above lines of code can be replaced by:

r = inet6_rth()
r.set(IPV6_RTHDR_TYPE_0, '3ffe::1', '3ffe::2')

We have kept the `set' method for `inet6_rth' objects in order to have the
same methods for all `inet6_rth' objects.

c = cmsg()
c.set(IPPROTO_IPV6, IPV6_RTHDR, r.data)
s = socket(AF_INET6, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (c,))

To receive routing header as ancillary data, you must enable IPV6_RECVRTHDR
socket option:

s.setsockopt(IPPROTO_IPV6, IPV6_RECVRTHDR, 1)

and proceed as follows:

r = inet6_rth()
alen = inet6_rth_space(IPV6_RTHDR_TYPE_0, 10) # expecting up to 10 nodes
alen = CMSG_SPACE(alen)
addr, data, adata, flags = s.recvmsg((1024,), alen)
for a in adata:
    if a.cmsg_level == IPPROTO_IPV6 and a.cmsg_type == IPV6_RTHDR:
        r.set_from_data(a.cmsg_data)
	r = r.get()
        print 'header:\n  nxt=%d, len=%d, type=%d, segleft=%d' % r[0][:-1]
        print 'segments:'
        for s in r[1:]:
            print '  %s' % s

To calculate ancillary data size, we used here function `inet6_rth_space'
(refer to RFC3542 for full description) instead of attribute `size'. In fact
`inet6_rth' objects have no `size' attribute because their size depends on
number of intermediate nodes.
  Output will be something like that:

header:
  nxt=17, len=4, type=0, segleft=2
segments:
  3ffe::1
  3ffe::2

  To be full compliant with RFC3542, other inet6_rth_XXX routines are also
available. If we suppose that `r' is the same `inet6_rth' object as above:

>>> print inet6_rth_segments(r)
2
>>> print inet6_rth_getaddr(r, 0)
3ffe::1
>>> inet6_rth_reverse(r, r)
>>> print r.get()
((0, 4, 0, 2, 0), '3ffe::2', '3ffe::1')

`ip6_mtuinfo' objects
---------------------

  To determine the current path MTU value for the destination of a given
CONNECTED socket(see RFC3542, section 11.4):

s = socket(AF_INET6, SOCK_STREAM)
s.connect(('::1', 20000))
m = ip6_mtuinfo() # object is created
data = s.getsockopt(IPPROTO_IPV6, IPV6_PATHMTU, m.size)
m.set_from_data(data)
print 'MTU: %u' % m.get()[1]

Output will be as follows:

MTU: 16384

Here, `16384' is the MTU of the loopback interface. For other use of
`ip6_mtuinfo' objects, refer to section 11 of RFC3542.

Note: option `IPV6_PATHMTU' is not (yet) implemented on Linux platforms.

Hop-by-Hop and Destination Options
----------------------------------

  Module `rfc3542' provides the seven inet6_opt_XXX functions defined in
RFC3542. They are:`inet6_opt_init', `inet6_opt_append', `inet6_opt_finish',
`inet6_opt_set_val', `inet6_opt_next', `inet6_opt_find' and
`inet6_opt_get_val'.
  To see how to use these methods from `rfc3542' module, reader is invitated
to read the Python script `inet6_opt.py' located in the `Test' directory of
the distribution. This script is the Python version of the example showed in
RFC3542 (see RFC3542 (p71-74), section 22: Appendix C: Examples Using the
inet6_opt_XXX() Functions).

An example when sending/receiving several ancillary data
--------------------------------------------------------

  To send hop limit and pktinfo simultaneously:

# building hop limit ancillary data
h = hoplimit()
h.set(16)
ch = cmsg()
ch.set(IPPROTO_IPV6, IPV6_HOPLIMIT, h.data)

# building pktinfo ancillary data
p = in6_pktinfo()
p.set('::', if_nametoindex('eth0'))
cp = cmsg()
cp.set(IPPROTO_IPV6, IPV6_PKTINFO, p.data)

s = socket(AF_INET6, SOCK_DGRAM)
s.sendmsg((host, port), ('This is ', 'a test'), (ch, cp))

  To receive hop limit and pktinfo as ancillary data:

s.setsockopt(IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
s.setsockopt(IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)

h = hoplimit()
p = in6_pktinfo()
alen = CMSG_SPACE(h.size) + CMSG_SPACE(p.size)

addr, data, adata, flags = s.recvmsg((1024,), alen)
for a in adata:
    if a.cmsg_level != IPPROTO_IPV6:
        continue
    if a.cmsg_type == IPV6_HOPLIMIT:
        h.set_from_data(a.cmsg_data)
        print 'hop limit: %u' % h.get()
    elif a.cmsg_type == IPV6_PKTINFO:
        p.set_from_data(a.cmsg_data)
	p = p.get()
        print "pktinfo: addr='%s', if=%s" % (p[0], if_indextoname(p[1]))

Implementation note:
====================

  `socket_ext' (resp. `rfc3542') module is composed of C extension module
`_socket_ext.c' (resp. `_rfc3542.c') located in `Modules' subdirectory and
a Python module `socket_ext.py' (resp `rfc3542.py') which acts as a front
end  to the C extension module and is located in top level directory.

Author
======

Yves Legrandgerard
email: ylg@pps.jussieu.fr
url: http://www.pps.jussieu.fr/~ylg/PyXAPI
