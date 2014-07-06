#!/usr/bin/env python

# rfc3542.py: front end for `_rfc3542.so'
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

from types import IntType, StringType
import struct

_have_rfc3542 = False
try:
    import _rfc3542
    from _rfc3542 import *

    _have_rfc3542 = True
    __doc__ =  _rfc3542.__doc__
except ImportError:
    pass

if _have_rfc3542:
    class SocketOptionInteger(object):
        """ internal class """

        def __init__(self):
            self.data = None
            self.size = struct.calcsize('L')
            
        def set(self, i, bound, msg):
            if type(i) != IntType:
                raise TypeError, '%s.set: argument must be an integer' % \
                      self.__class__.__name__
            if not 0 <= i <= bound:
                raise error, msg % self.__class__.__name__
            self.data = struct.pack('L', i)
            
        def set_from_data(self, data):
            if type(data) != StringType:
                raise TypeError, \
                      '%s.set_from_data: argument must be a string' % \
                      self.__class__.__name__
            try:
                struct.unpack('L', data)[0]
            except:
                raise TypeError, '%s.set_from_data: invalid data' % \
                      self.__class__.__name__
            self.data = data
            
        def get(self):
            if self.data == None:
                return None
            return struct.unpack('L', self.data)[0]

    class hoplimit(SocketOptionInteger):
        """HOPLIMIT objects are defined to handle hoplimit option

hoplimit() -> HOPLIMIT object

Create a new HOPLIMIT object

Methods of HOPLIMIT objects:

set(string, int) -- initialize a hop limit option
set_from_data(string) -- initialize a hop limit option from raw data
get() -- return hop limit

Attributes of HOPLIMIT objects:

data -- HOPLIMIT object as a raw string
size -- size in bytes of `hoplimit' option (not HOPLIMIT object)"""
        
        def __init__(self):
            SocketOptionInteger.__init__(self)
            
        def set(self, i):
            """set(int) -> None
            
Initialize HOPLIMIT object. Arg1 is hop limit.
Return None."""
            
            SocketOptionInteger.set(self, i, 0xff, '%s: invalid hop limit')

        def set_from_data(self, data):
            """set_from_data(string) -> None
        
Initialize HOPLIMIT object from raw data (arg1).
Return None."""
            
            SocketOptionInteger.set_from_data(self, data)

        def get(self):
            """get() -> int

Return hop limit."""

            return SocketOptionInteger.get(self)
            
    class tclass(SocketOptionInteger):
        """TCLASS objects are defined to handle traffic class option

tclass() -> TCLASS object

Create a new TCLASS object

Methods of TCLASS objects:

set(string, int) -- initialize a traffic class option
set_from_data(string) -- initialize a traffic class option from raw data
get() -- return traffic class

Attributes of TCLASS objects:

data -- TCLASS object as a raw string
size -- size in bytes of `tclass' option (not TCLASS object)"""

        def __init__(self):
            SocketOptionInteger.__init__(self)
         
        def set(self, i):
            """set(int) -> None
            
Initialize TCLASS object. Arg1 is traffic class.
Return None."""
            
            SocketOptionInteger.set(self, i, 0xff,
                                    '%s: invalid traffic class value')

        def set_from_data(self, data):
            """set_from_data(string) -> None
        
Initialize TCLASS object from raw data (arg1).
Return None."""
            
            SocketOptionInteger.set_from_data(self, data)

        def get(self):
            """get() -> int

Return traffic class."""

            return SocketOptionInteger.get(self)
