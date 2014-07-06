#!/usr/bin/env python

# This example is the Python version of the example showed in RFC3542.
# See RFC3542 (p65-71), section 21: Appendix B: Examples Using the
# inet6_rth_XXX() Functions.


from socket_ext import *
from rfc3542 import *

UDP_TEST_PORT = 20000

##############################
# Receiving a Routing Header #
##############################

# Print a INET6_RTH object (routing header), using method get().

def print_rth(rth):
    r = rth.get()
    print 'header:\n  nxt=%d, len=%d, type=%d, segleft=%d' % r[0][:-1]
    print 'segments:'
    for s in r[1:]:
        print '  %s' % s

# Parse ancillary data returned by recvmsg(). `adata' is  a tuple of CMSG
# object.

def parse_ancillary_data(adata):
    for c in adata:
        if c.cmsg_level == IPPROTO_IPV6 and c.cmsg_type == IPV6_RTHDR:
            r = inet6_rth()
            r.set_from_data(c.cmsg_data)
            return r
# Bind socket, set IPV6_RECVRTHDR option and execute recvmsg()

def recv_with_routing_header(sock):
    sock.bind(('', UDP_TEST_PORT))
    sock.setsockopt(IPPROTO_IPV6, IPV6_RECVRTHDR, 1)
    
    # Expecting up to 100 intermediate nodes. Too much in fact because
    # we are waiting for only 3 nodes. Keep that value to strictly follow
    # RFC3542 example
    extlen = inet6_rth_space(IPV6_RTHDR_TYPE_0, 100)
    
    addr, data, adata, flags = sock.recvmsg((1024,), CMSG_SPACE(extlen))

    # Doing some error checking
    if flags & MSG_TRUNC:
        print 'Warning: data are truncated'
    if flags & MSG_CTRUNC:
        print 'Warning: ancillary data are truncated'
    return addr, data, adata

if __name__ =='__main__':
    sock = socket(AF_INET6, SOCK_DGRAM)
    addr, data, adata = recv_with_routing_header(sock)
    print 'Received from: ', addr, ','
    print 'data:'
    print '  ', data
    if adata:
        print 'with routing header:'
        rth = parse_ancillary_data(adata)
        print_rth(rth)

        # As in RFC3542 example, we send back (same) data with routing
        # header reversed
        print '\nReverse routing header, it is now:'
        inet6_rth_reverse(rth, rth)
        print_rth(rth)
        print 'Send back (same data)...'
        c = cmsg()
        c.set(IPPROTO_IPV6, IPV6_RTHDR, rth.data)
        ret = sock.sendmsg(addr, data, (c,))
        print 'Done (%d bytes sent).' % ret
