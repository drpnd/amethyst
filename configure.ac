#
# Copyright (c) 2013-2014 Scyphus Solutions Co. Ltd.  All rights reserved.
# Authors:
#      Hirochika Asai  <asai@jar.jp>
#

AC_PREREQ(2.59)
AC_INIT([amethyst], [0.2.0], [bug@scyphus.co.jp])
AC_CONFIG_SRCDIR([amethyst.c])
AC_CONFIG_HEADER([config.h])

# Get hostname and other information.
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE
AC_SUBST(SUBDIRS)

# arguments
AC_ARG_ENABLE(debug,
  [  --enable-debug    Turn on debugging [default no]],
  [case "${enableval}" in
    yes) debug=yes; AC_MSG_RESULT(Checking for debug... yes); AC_DEFINE(DEBUG, 1, debugging option) ;;
    no)  debug=no;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
  esac],[debug=no])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

## Network
if test x"${enable_ipv4}" = x"no";then
   AC_DEFINE(ENABLE_IP4, 0, enable IPv4)
else
   AC_DEFINE(ENABLE_IP4, 1, enable IPv4)
fi
if test x"${enable_ipv6}" = x"no";then
   AC_DEFINE(ENABLE_IP6, 0, enable IPv6)
else
   AC_DEFINE(ENABLE_IP6, 1, enable IPv6)
fi

# Checks for hosts
case $host_os in
     freebsd*)
        AC_DEFINE(TARGET_FREEBSD, 1, running on FreeBSD)
        arch=freebsd
        ;;
     netbsd*)
        AC_DEFINE(TARGET_NETBSD, 1, running on NetBSD)
        arch=netbsd
        ;;
     darwin*)
        AC_DEFINE(TARGET_DARWIN, 1, running on Mac OS X)
        arch=darwin
        ;;
     linux*)
        AC_DEFINE(TARGET_LINUX, 1, running on Linux)
        arch=linux
        ;;
     *) ;;
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
#AC_PROG_LIBTOOL

# Checks for libraries.

enable_logfile_mask=${enable_logfile_mask:-0644}
AC_DEFINE_UNQUOTED(LOGFILE_MASK, ${enable_logfile_mask}, Mask for log files)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
#AC_CHECK_FUNCS([])


# configure date
CONFDATE=`date '+%Y%m%d'`
AC_SUBST(CONFDATE)

# set paths for state directory
if test "${prefix}" = "NONE"; then
  amethyst_statedir_prefix="";
else
  amethyst_statedir_prefix=${prefix}
fi
if test "${localstatedir}" = '${prefix}/var'; then
  AC_CACHE_CHECK(state directory,ac_cv_statedir,
  [for AMETHYST_STATE_DIR in ${amethyst_statedir_prefix}/var/run dnl
                        ${amethyst_statedir_prefix}/var/adm dnl
                        ${amethyst_statedir_prefix}/etc dnl
                        /var/run dnl
                        /var/adm dnl
                        /etc dnl
                        /dev/null;
  do
    test -d $AMETHYST_STATE_DIR && break
  done
  amethyst_statedir=$AMETHYST_STATE_DIR])
else
  amethyst_statedir=${localstatedir}
  AC_MSG_CHECKING(directory to use for state file)
  AC_MSG_RESULT(${amethyst_statedir})
  AC_SUBST(amethyst_statedir)
fi
if test $amethyst_statedir = "/dev/null"; then
    AC_MSG_ERROR('STATE DIRECTORY NOT FOUND! FIX OR SPECIFY --localstatedir!')
fi
AC_DEFINE_UNQUOTED(PATH_ATOMOS_PID, "$amethyst_statedir/atomos.pid", atomos PID)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
amethyst configuration
------------------------
amethyst version         : ${PACKAGE_VERSION}
host operationg system  : ${host_os}
source code location    : ${srcdir}
compiler                : ${CC}
compiler flags          : ${CFLAGS}
linker flags            : ${LDFLAGS} ${LIBS}
state file directory    : ${amethyst_statedir}
log file mask           : ${enable_logfile_mask}
"
