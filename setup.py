#!/usr/bin/env python

from distutils.core import setup, Extension

DESCRIPTION = 'Python Socket Module Extension + ' + \
              'Advanced Socket API for IPv6 (RFC 3542)'

ext_modules = [Extension('_socket_ext', ['Modules/socket_ext.c'],
                         include_dirs=['.', 'Include'],
                         library_dirs=['/usr/local/v6/lib'],
                         libraries=['inet6'])]
py_modules = ['socket_ext']

ipv6 = 'yes'
if ipv6 == 'yes':
    py_modules.append('rfc3542')
    ext_modules.append(Extension('_rfc3542', ['Modules/rfc3542.c'],
                                 include_dirs=['.', 'Include'],
                                 library_dirs=['/usr/local/v6/lib'],
                                 libraries=['inet6']))
    
setup(name='PyXAPI',
      version='0.1',
      description=DESCRIPTION,
      author='Yves Legrandgerard',
      author_email='ylg@pps.jussieu.fr',
      url='http://www.pps.jussieu.fr/~ylg/PyXAPI/',
      py_modules=py_modules,
      ext_modules=ext_modules,
     )
