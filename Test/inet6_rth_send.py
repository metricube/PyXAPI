#!/usr/bin/env python

# This example is the Python version of the example showed in RFC3542.
# See RFC3542 (p65-71), section 21: Appendix B: Examples Using the
# inet6_rth_XXX() Functions.


from socket_ext import *
from rfc3542 import *

UDP_TEST_PORT = 20000
DATA_TEST = ('this is', ' a test')

############################
# Sending a Routing Header #
############################

# Building ancillary data with routing header

def make_ancillary_data(I1, I2, I3):
    r = inet6_rth()
    r = inet6_rth_init(r, IPV6_RTHDR_TYPE_0, 3)
    inet6_rth_add(r, I1)
    inet6_rth_add(r, I2)
    inet6_rth_add(r, I3)
    c = cmsg()
    c.set(IPPROTO_IPV6, IPV6_RTHDR, r.data)
    return c

# Sending `DATA_TEST' with routing header as ancillary data. The
# choice for UDP (and `UDP_TEST_PORT') is simply for illustration

def send_with_routing_header(I1, I2, I3, DST):
    sock = socket(AF_INET6, SOCK_DGRAM)
    adata = (make_ancillary_data(I1, I2, I3),)
    return sock.sendmsg((DST, UDP_TEST_PORT), DATA_TEST, adata)

if __name__ == '__main__':
    import sys

    if len(sys.argv) != 5:
        print 'Usage: %s I1 I2 I3 DST' % sys.argv[0]
        sys.exit(1)
    try:
        ret = apply(send_with_routing_header, sys.argv[1:])
        print 'Sent %d bytes to: %s via:' % (ret, sys.argv[-1])
        print 3 * '  %s\n' % tuple(sys.argv[1:-1]),
    except (error, gaierror), msg:
        print msg
        sys.exit(1)
    sys.exit(0)
