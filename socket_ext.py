#!/usr/bin/env python

# socket_ext.py: front end for `_socket_ext.so'
# Copyright (C) 2004  Yves Legrandgerard (ylg@pps.jussieu.fr)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import socket
from socket import *

_have_socket_ext = False
try:
    import _socket_ext
    from _socket_ext import *

    _have_socket_ext = True
    __doc__ =  _socket_ext.__doc__
except ImportError:
    pass

if _have_socket_ext:
    class socket(SocketType):
        def __init__(self, family, type_, proto=0):
            SocketType.__init__(self, family, type_, proto)

        def sendmsg(self, arg, *args):
            if hasattr(self, "_sock"):
                sock = self._sock
            else:
                sock = self
            if args and type(args[0]) == type(()) and \
               (len(args[0]) == 0 or type(args[0][0]) != CMSGType):
                try:
                    addr = apply(getaddrinfo, arg[:2] + (0, SOCK_DGRAM))[0]
                    family = addr[0]
                    addr = addr[-1][0:2] + arg[2:]
                except gaierror, msg:
                    raise gaierror, 'sendmsg: %s' % msg
                except:
                    raise exterror, 'sendmsg: invalid sockaddr'
                return _socket_ext._sendmsg(sock, family, addr, *args)
            return _socket_ext._sendmsg(sock, arg, *args)
        
        sendmsg.__doc__ = _socket_ext._sendmsg.__doc__

        def recvmsg(self, *args):
            if hasattr(self, "_sock"):
                sock = self._sock
            else:
                sock = self
            return _socket_ext._recvmsg(sock, *args)
        
        recvmsg.__doc__ = _socket_ext._recvmsg.__doc__
