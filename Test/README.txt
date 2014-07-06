Examples for  PyXAPI version 0.1
================================

To run examples below, do no forget to execute `make test' before from the
toplevel directory.

- one_ping6.py: this is a (very!) simplified version of the well known command
  `ping6'. `one_ping6.py' send one ICMPv6 Echo Request to some destination
  via (optional) intermediate nodes. Then it waits for ICMPv6 Echo Reply
  and prints some ancillary data (possibly) received as hop limit and routing
  header. To run this program, as `root' (`one_ping6.py' needs `SOCK_RAW'
  socket), type:
    >>> ./one_ping6.py -s 123 -d 'This is ' -d 'a test' i1 i2 i3 dest
  where `i1', `i2' and `i3' are intermediate nodes, `dest' is destination.
  Output will be something like that:
    Sending one ICMPv6 Echo Request to iode.ipv6
    via:
      i1
      i2
      i3
    Received from 3ffe:200:100:1::53 , hoplimit=49
    ICMPv6 Echo Reply:
      Type:        129
      Code:        0
      Checksum:    0xc20c
      Identifier:  38020
      Sequence:    123
      Data:        14 Byte(s)

- inet6_rth_send.py & inet6_rth_recv.py: this is the Python version of the
  example showed in RFC3542. It shows how to send/receive a routing header
  (of type 0). See RFC3542 (p65-71), section 21: Appendix B: Examples Using
  the inet6_rth_XXX() Functions.
  To run this example, first launch the server in some window:
    >>> ./inet6_rth_recv.py
  In an other window, run the client:
    >>> ./inet6_rth_send.py I1 I2 I3 your_host
    Sent 14 bytes to: your_host via:
      I1
      I2
      I3
  Here I1, I2 and I3 are the three (IPv6) intermediate nodes and `your_host'
  is the host on which server has been launched (not localhost (::1)). In
  server's window, output would be something as follows:
    Received from:  ('3ffe:200:100:1:203:47ff:fe2d:dbed', 2294, 0, 0) ,
    data:
      ('this is a test',)
    with routing header:
    header:
      nxt=17, len=6, type=0, segleft=0
    segments:
      3ffe:200:100:1::53
      3ffe:200:100:1:290:27ff:feac:7980
      3ffe:200:100:1:204:9aff:fee4:3640

    Reverse routing header, it is now:
    header:
      nxt=17, len=6, type=0, segleft=3
    segments:
      3ffe:200:100:1:204:9aff:fee4:3640
      3ffe:200:100:1:290:27ff:feac:7980
      3ffe:200:100:1::53
    Send back (same data)...
    Done (14 bytes sent).

- inet6_opt.py:  this is the Python version of the example showed in RFC3542.
  It shows how to build and parse Hop-by-Hop and Destination options. See
  RFC3542 (p71-74), section 22: Appendix C: Examples Using the inet6_opt_XXX()
  Functions.
  To execute, just type in `Test' directory:
    >>> ./inet6_opt.py
    nxt 0, len 3 (bytes 32)
    Received opt 10 len 12
    X 4-byte field 0x12345678
    X 4-byte field 0x102030405060708
    Received opt 20 len 7
    Y 1-byte field 0x01
    Y 2-byte field 0x1331
    Y 4-byte field 0x1020304