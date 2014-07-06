dnl Process this file with autoconf 2.0 or later to make a configure script.

m4_define(PyXAPI_NAME, PyXAPI)
m4_define(PyXAPI_VERSION, 0.1)
m4_define(AUTHOR_EMAIL, ylg@pps.jussieu.fr)

m4_define(PYTHON_VERSION_REQUIRED, 2.3.3)
m4_define(PYTHON_VERSION_MSG, [version PYTHON_VERSION_REQUIRED or newer])

AC_PREREQ(2.57)
AC_INIT(PyXAPI_NAME, PyXAPI_VERSION, AUTHOR_EMAIL,
  [PyXAPI-PyXAPI_VERSION.tar.gz])

AC_SUBST(NAME)
NAME=PyXAPI_NAME
AC_SUBST(VERSION)
VERSION=PyXAPI_VERSION
AC_SUBST(EMAIL)
EMAIL=AUTHOR_EMAIL

AC_CONFIG_HEADERS([pyxapi.h])

AH_TOP([
#ifndef PyXAPI_H
#define PyXAPI_H
])
AH_BOTTOM([
#endif /*PyXAPI_H*/
])

AC_PROG_CC

dnl Checks for UNIX variants that set C preprocessor variables
AC_AIX
AC_MINIX

dnl AC_PROG_EGREP

dnl Checking for ipv6 support (adapted from Python-2.3.3 distribution)

AC_MSG_CHECKING([if --enable-ipv6 is specified])
AC_ARG_ENABLE(ipv6,
  [  --enable-ipv6           Enable ipv6 support (default)
  --disable-ipv6          Disable ipv6 support (rfc3542 module will be not
                          available)
  ],
  [case $enableval in
   no)
     AC_MSG_RESULT(no)
     ipv6=no
     ;;
   *)
     AC_MSG_RESULT(yes)
     ipv6=yes
     ;;
   esac
  ],
  [AC_TRY_RUN(
     [#include <sys/types.h>
      #include <sys/socket.h>
      main()
      {
        if (socket(AF_INET6, SOCK_STREAM, 0) < 0)
          exit(1);
        else
          exit(0);
      }
     ],
     AC_MSG_RESULT(yes)
     ipv6=yes,
     AC_MSG_RESULT(no)
     ipv6=no
   )
   if test $ipv6 = yes; then
     AC_MSG_CHECKING(if RFC3493 API is available)
     AC_TRY_COMPILE(
       [#include <sys/types.h>
        #include <netinet/in.h>
       ],
       [struct sockaddr_in6 x; x.sin6_scope_id;],
       AC_MSG_RESULT(yes)
       ipv6=yes,
       AC_MSG_RESULT(no, IPv6 disabled)
       ipv6=no
     )
   fi
  ]
)

AC_SUBST(IPV6)
IPV6=$ipv6

dnl Checking for ipv6 stack type and setting IPv6 librairies
dnl (adapted from Python-2.3.3 distribution)

ipv6type=unknown
ipv6lib=none
ipv6trylibc=no

if test $ipv6 = yes; then
  AC_MSG_CHECKING([ipv6 stack type])
  for i in inria kame linux-glibc linux-inet6 solaris toshiba v6d zeta;
    do
      case $i in
      inria)
	dnl http://www.kame.net/
	AC_EGREP_CPP(yes,
          [#include <netinet/in.h>
           #ifdef IPV6_INRIA_VERSION
           yes
           #endif
          ],
          [ipv6type=$i]
        )
        ;;
      kame)
        dnl http://www.kame.net/
        AC_EGREP_CPP(yes,
          [#include <netinet/in.h>
           #ifdef __KAME__
           yes
           #endif
          ],
          [ipv6type=$i;
           ipv6lib=inet6
           ipv6libdir=/usr/local/v6/lib
           ipv6trylibc=yes
          ]
        )
        ;;
      linux-glibc)
        dnl http://www.v6.linux.or.jp/
        AC_EGREP_CPP(yes,
          [#include <features.h>
           #if defined(__GLIBC__) && \
             ((__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1) || (__GLIBC__ > 2))
           yes
           #endif
          ],
          [ipv6type=$i;
           ipv6trylibc=yes
          ]
        )
        ;;
      linux-inet6)
        dnl http://www.v6.linux.or.jp/
        if test -d /usr/inet6; then
	  ipv6type=$i
	  ipv6lib=inet6
          ipv6libdir=/usr/inet6/lib
          BASECFLAGS="-I/usr/inet6/include $BASECFLAGS"
        fi
        ;;
      solaris)
        if test -f /etc/netconfig; then
          if /usr/xpg4/bin/grep -q tcp6 /etc/netconfig; then
            ipv6type=$i
            ipv6trylibc=yes
          fi
        fi
        ;;
      toshiba)
        AC_EGREP_CPP(yes,
          [#include <sys/param.h>
           #ifdef _TOSHIBA_INET6
           yes
           #endif
          ],
          [ipv6type=$i;
           ipv6lib=inet6;
           ipv6libdir=/usr/local/v6/lib
          ]
        )
        ;;
      v6d)
        AC_EGREP_CPP(yes,
          [#include </usr/local/v6/include/sys/v6config.h>
           #ifdef __V6D__
           yes
           #endif
          ],
          [ipv6type=$i;
           ipv6lib=v6;
           ipv6libdir=/usr/local/v6/lib;
           BASECFLAGS="-I/usr/local/v6/include $BASECFLAGS"
          ]
        )
        ;;
      zeta)
        AC_EGREP_CPP(yes,
          [#include <sys/param.h>
           #ifdef _ZETA_MINAMI_INET6
           yes
           #endif
          ],
          [ipv6type=$i;
           ipv6lib=inet6;
           ipv6libdir=/usr/local/v6/lib
          ]
        )
	;;
      esac
      if test $ipv6type != unknown; then
        break
      fi
    done
  AC_MSG_RESULT($ipv6type)
fi

LIBRARY_DIRS="[[]]"
LIBRARIES="[[]]"
if test $ipv6 = yes -a $ipv6lib != none; then
  if test -d $ipv6libdir -a -f $ipv6libdir/lib$ipv6lib.a; then
    LIBRARY_DIRS="[['$ipv6libdir']]"
    LIBRARIES="[['$ipv6lib']]"
    LIBS="-L$ipv6libdir -l$ipv6lib $LIBS"
    echo "using lib$ipv6lib"
  else
    if test $ipv6trylibc = yes; then
      echo "using libc"
    else
      echo 'Fatal: no $ipv6lib library found. Cannot continue.'
      echo "You need to fetch lib$ipv6lib.a from appropriate"
      echo 'ipv6 kit and compile beforehand.'
      exit 1
    fi
  fi
fi

AC_SUBST(LIBRARY_DIRS)
LIBRARY_DIRS=$LIBRARY_DIRS
AC_SUBST(LIBRARIES)
LIBRARIES=$LIBRARIES

dnl Checking for Python, Python version, socket module and Python IPv6 support

AC_PATH_PROG(ac_python_program, python, python_not_found)
if test $ac_python_program = python_not_found; then
  AC_MSG_FAILURE([you must have Python (PYTHON_VERSION_MSG) installed])
fi

AC_MSG_CHECKING(for python version)
answer=`$ac_python_program <<EOF
try:
  import sys, string
  if string.split(sys.version)[[0]] < 'PYTHON_VERSION_REQUIRED':
    print 1
  else:
    print 0
except:
  print 2
`
case $answer in
  0)
   AC_MSG_RESULT(ok)
   ;;
  1)
   AC_MSG_RESULT([])
   AC_MSG_FAILURE([Python version is too old: PYTHON_VERSION_MSG is required])
   ;;
  2)
   AC_MSG_RESULT([])
   AC_MSG_FAILURE([cannot get python version ($ac_python_program)])
   ;;
esac

AC_MSG_CHECKING(for python socket module)
answer=`$ac_python_program <<EOF
try:
  import socket
  from socket import *
  print 0
except:
  print 1
`
if test $answer -eq 0; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  AC_MSG_FAILURE([you must have python compiled with socket module])
fi

if test $ipv6 = yes; then
  AC_MSG_CHECKING(for python ipv6 support)
  answer=`$ac_python_program <<EOF
import socket
if socket.has_ipv6:
  print 0
else:
  print 1
`
  if test $answer -eq 0; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
    AC_MSG_FAILURE([you must have python compiled with ipv6 support])
  fi
fi

AC_SUBST(PYTHON_PROGRAM)
PYTHON_PROGRAM=$ac_python_program

dnl Checking for recvmsg, sendmsg, struct msghdr and struct cmsghdr

AC_CHECK_FUNC(recvmsg, [], AC_MSG_FAILURE([`recvmsg' function is missing]))
AC_CHECK_FUNC(sendmsg, [], AC_MSG_FAILURE([`sendmsg' function is missing]))
AC_MSG_CHECKING(for struct msghdr)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>
  ],
  [struct msghdr m; m.msg_name; m.msg_namelen; m.msg_iov; m.msg_iovlen;
   m.msg_control; m.msg_controllen; m.msg_flags;
  ],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  AC_MSG_FAILURE([`struct msghdr' type is missing])
)
AC_MSG_CHECKING(for struct cmsghdr)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>
  ],
  [struct cmsghdr c; c.cmsg_len; c.cmsg_level; c.cmsg_type;],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  AC_MSG_FAILURE([`struct cmsghdr' type is missing])
)

dnl If operating system is Solaris (version <= 9), macros CMSG_DATA and
dnl CMSG_LEN are not defined

ac_have_sunos=no
ac_sys_system=`uname -s`
case $ac_sys_system in
  SunOS*) AC_DEFINE(HAVE_SUNOS, 1, [Define to 1 if you are using Solaris])
          ac_have_sunos=yes;;
esac

dnl Checking for CMSG macros

AC_MSG_CHECKING([for macro CMSG_LEN])
AC_TRY_LINK(
  [#include <sys/types.h>
   #include <sys/socket.h>
  ],
  [CMSG_LEN(4);],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  if test $ac_have_sunos = no; then
    AC_MSG_FAILURE([`CMSG_LEN' macro is missing])
  fi
)

AC_MSG_CHECKING([for macro CMSG_SPACE])
AC_TRY_LINK(
  [#include <sys/types.h>
   #include <sys/socket.h>
  ],
  [CMSG_SPACE(4);],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  if test $ac_have_sunos = no; then
    AC_MSG_FAILURE([`CMSG_SPACE' macro is missing])
  fi
)
  
AC_MSG_CHECKING([for macro CMSG_FIRSTHDR])
AC_TRY_LINK(
  [#ifndef NULL
   #define NULL 0
   #endif
   #include <sys/types.h>
   #include <sys/socket.h>
  ],
  [struct msghdr *m; CMSG_FIRSTHDR(m);],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  AC_MSG_FAILURE([`CMSG_FIRSTHDR' macro is missing])
)

AC_MSG_CHECKING([for macro CMSG_NXTHDR])
AC_TRY_LINK(
  [#ifndef NULL
   #define NULL 0
   #endif
   #include <sys/types.h>
   #include <sys/socket.h>
  ],
  [struct msghdr *m; struct cmsghdr *c; CMSG_NXTHDR(m, c);],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  AC_MSG_FAILURE([`CMSG_NXTHDR' macro is missing])
)

AC_MSG_CHECKING([for macro CMSG_DATA])
AC_TRY_LINK(
  [#include <sys/types.h>
   #include <sys/socket.h>
  ],
  [struct cmsghdr *c; CMSG_DATA(c);],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  AC_MSG_FAILURE([`CMSG_DATA' macro is missing])
)

dnl Checking for getaddinfo, getnameinfo and freeaddrinfo

AC_CHECK_FUNC(getaddrinfo, [],
  AC_MSG_FAILURE([`getaddrinfo' function is missing])
)

AC_CHECK_FUNC(getnameinfo, [],
  AC_MSG_FAILURE([`getnameinfo' function is missing])
)

AC_CHECK_FUNC(freeaddrinfo, [],
  AC_MSG_FAILURE([`freeaddrinfo' function is missing])
)

dnl Checking for if_nametoindex, if_indextoname and if_nameindex. They are
dnl defined in RFC3493 but not available from Python (<= 2.4) socket module

AC_CHECK_FUNCS(if_nametoindex if_indextoname)
AC_CHECK_FUNCS(if_nameindex if_freenameindex)
AC_MSG_CHECKING(for struct if_nameindex)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>
   #include <net/if.h>
  ],
  [struct if_nameindex i; i.if_index; i.if_name;],
  [AC_DEFINE(HAVE_STRUCT_IF_NAMEINDEX, 1,
     [Define to 1 if you have the type struct if_nameindex]
   )
   AC_MSG_RESULT(yes)
  ],
   AC_MSG_RESULT(no)
)

dnl Checks if we have ipv6 support (BEGIN)
if test $ipv6 = yes; then

AC_C_BIGENDIAN()

dnl Checking for POSIX types uint8_t and uint32_t

AC_CHECK_HEADERS(stdint.h)

AC_MSG_CHECKING(for POSIX type uint8_t)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #if HAVE_STDINT_H
   #include <stdint.h>
   #endif
  ],
  [uint8_t u;],
  [AC_DEFINE(HAVE_UINT8_T, 1,
     [Define to 1 if you have the POSIX type uint8_t]
   )
   AC_MSG_RESULT(yes)
  ],
  AC_MSG_RESULT(no)
)

AC_MSG_CHECKING(for POSIX type uint32_t)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #if HAVE_STDINT_H
   #include <stdint.h>
   #endif
  ],
  [uint32_t u;],
  [AC_DEFINE(HAVE_UINT32_T, 1,
     [Define to 1 if you have the POSIX type uint32_t]
   )
   AC_MSG_RESULT(yes)
  ],
  AC_MSG_RESULT(no)
)

dnl Checking for struct icmp6_filter and struct in6_pktinfo

AC_MSG_CHECKING(for struct icmp6_filter)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <netinet/in.h>
   #include <netinet/icmp6.h>
  ],
  [struct icmp6_filter f; int i = ICMP6_FILTER],
  [AC_DEFINE(HAVE_STRUCT_ICMP6_FILTER, 1,
     [Define to 1 if you have the type struct icmp6_filter]
   )
   AC_MSG_RESULT(yes)
  ],
  AC_MSG_RESULT(no)
)

AC_MSG_CHECKING(for struct in6_pktinfo)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <netinet/in.h>
  ],
  [struct in6_pktinfo p; p.ipi6_addr; p.ipi6_ifindex;],
  [AC_DEFINE(HAVE_STRUCT_IN6_PKTINFO, 1,
     [Define to 1 if you have the type struct in6_pktinfo]
   )
   AC_MSG_RESULT(yes)
  ],
   AC_MSG_RESULT(no)
)

dnl Checking for `inet6_rth_*' functions

AC_CHECK_FUNCS(inet6_rth_space inet6_rth_init inet6_rth_add)
AC_CHECK_FUNCS(inet6_rth_reverse inet6_rth_segments inet6_rth_getaddr)

AC_MSG_CHECKING(for struct ip6_rthdr)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <netinet/in.h>
   #include <netinet/ip6.h>
  ],
  [struct ip6_rthdr r; r.ip6r_nxt; r.ip6r_len; r.ip6r_type;
   r.ip6r_segleft;
  ],
  [AC_DEFINE(HAVE_STRUCT_IP6_RTHDR, 1,
     [Define to 1 if you have the type struct ip6_rthdr]
   )
   AC_MSG_RESULT(yes)
  ],
   AC_MSG_RESULT(no)
)

AC_MSG_CHECKING(for struct ip6_rthdr0)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <netinet/in.h>
   #include <netinet/ip6.h>
  ],
  [struct ip6_rthdr0 r; r.ip6r0_nxt; r.ip6r0_len; r.ip6r0_type;
   r.ip6r0_segleft; r.ip6r0_reserved;
  ],
  [AC_DEFINE(HAVE_STRUCT_IP6_RTHDR0, 1,
     [Define to 1 if you have the type struct ip6_rthdr0]
   )
   AC_MSG_RESULT(yes)
  ],
   AC_MSG_RESULT(no)
)

dnl Checking for `inet6_opt_*' functions

AC_CHECK_FUNCS(inet6_opt_init inet6_opt_append inet6_opt_finish)
AC_CHECK_FUNCS(inet6_opt_set_val inet6_opt_next inet6_opt_find)
AC_CHECK_FUNCS(inet6_opt_get_val)

AC_MSG_CHECKING(for struct ip6_opt)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <netinet/in.h>
   #include <netinet/ip6.h>
  ],
  [struct ip6_opt o; o.ip6o_type; o.ip6o_len;],
  [AC_DEFINE(HAVE_STRUCT_IP6_OPT, 1,
     [Define to 1 if you have the type struct ip6_opt]
   )
   AC_MSG_RESULT(yes)
  ],
   AC_MSG_RESULT(no)
)

dnl Checking for Path MTU stuff

AC_MSG_CHECKING(for struct ip6_mtuinfo)
AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <netinet/in.h>
  ],
  [struct ip6_mtuinfo m; m.ip6m_addr; m.ip6m_mtu;],
  [AC_DEFINE(HAVE_STRUCT_IP6_MTUINFO, 1,
     [Define to 1 if you have the type struct ip6_mtuinfo]
   )
   AC_MSG_RESULT(yes)
  ],
   AC_MSG_RESULT(no)
)

fi
dnl Checks if we have ipv6 support (END)

AC_CONFIG_FILES(Makefile setup.py)

AC_OUTPUT
