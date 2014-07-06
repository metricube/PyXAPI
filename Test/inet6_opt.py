#!/usr/bin/env python

# This example is the Python version of the example showed in RFC3542.
# See RFC3542 (p71-74), section 22: Appendix C: Examples Using the
# inet6_opt_XXX() Functions.

import struct
from rfc3542 import *

# These values have no meaning. Just for this example.

OPT_X = 10
OPT_Y = 20

####################
# Building Options #
####################

currentlen = inet6_opt_init()
currentlen = inet6_opt_append(currentlen, OPT_X, 12, 8)
currentlen = inet6_opt_append(currentlen, OPT_Y, 7, 4)
currentlen = inet6_opt_finish(currentlen);
extlen = currentlen

opt = inet6_opt()	# Creating an INET6_OPT object
opt.set(extlen)		# Initialization (with `extlen' previously computed)

currentlen = inet6_opt_init(opt, extlen)

# Setting OPT_X option

currentlen = inet6_opt_append(opt, currentlen, OPT_X, 12, 8)
offset = 0
value4 = struct.pack('L', 0x12345678)
offset = inet6_opt_set_val(opt, offset, value4)
value8 = struct.pack('Q', 0x0102030405060708)
offset = inet6_opt_set_val(opt, offset, value8)

# Setting OPT_Y option

currentlen = inet6_opt_append(opt, currentlen, OPT_Y, 7, 4)
offset = 0;
value1 = struct.pack('B', 0x01)
offset = inet6_opt_set_val(opt, offset, value1)
value2 = struct.pack('H', 0x1331)
offset = inet6_opt_set_val(opt, offset, value2)
value4 = struct.pack('L', 0x01020304)
offset = inet6_opt_set_val(opt, offset, value4)

# Adding TLV options to option header

currentlen = inet6_opt_finish(opt, currentlen)

############################
# Parsing Received Options #
############################

def print_opt(opt):
    ext = opt.get()
    print 'nxt %u, len %u (bytes %d)' % (ext[0], ext[1], (ext[1] + 1) << 3)
    currentlen = 0;
    while True:
        try:
            currentlen, type, len = inet6_opt_next(opt, currentlen)
        except:
            break
        print 'Received opt %u len %u' % (type, len)
        if type == OPT_X:
            offset = 0
            offset, value = \
                    inet6_opt_get_val(opt, offset, struct.calcsize('L'))
            print 'X 4-byte field 0x%.2x' % struct.unpack('L', value)[0]
            offset, value = \
                    inet6_opt_get_val(opt, offset, struct.calcsize('Q'))
            print 'X 4-byte field 0x%.2x' % struct.unpack('Q', value)[0]
        elif type == OPT_Y:
            offset = 0
            offset, value = \
                    inet6_opt_get_val(opt, offset, struct.calcsize('B'))
            print 'Y 1-byte field 0x%.2x' % struct.unpack('B', value)[0]
            offset, value = \
                    inet6_opt_get_val(opt, offset, struct.calcsize('H'))
            print 'Y 2-byte field 0x%.2x' % struct.unpack('H', value)[0]
            offset, value = \
                    inet6_opt_get_val(opt, offset, struct.calcsize('L'))
            print 'Y 4-byte field 0x%.2x' % struct.unpack('L', value)[0]

if __name__ == '__main__':
    print_opt(opt)
