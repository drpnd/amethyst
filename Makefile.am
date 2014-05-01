#
# $Id$
#
# Copyright (c) 2013 Scyphus Solutions Co. Ltd.  All rights reserved.
# Authors:
#      Hirochika Asai  <asai@scyphus.co.jp>
#

EXTRA_DIST = conf/amethyst.conf cgi/dns.cgi

bin_PROGRAMS = amethyst atomos
amethyst_SOURCES = amethyst.c \
	common/pid_output.c common/error.c \
	common/pid_output.h common/error.h
atomos_SOURCES = atomos.c dns.c cgi.c cfg.c str.c zone.c selector.c \
	dns.h dns_private.h zone.h selector.h \
	scfg.c scfg.h scfg_private.h tokenizer.c \
	common/pid_output.c common/error.c common/daemon.c common/log.c \
	common/server.c common/bsconv.c common/rbtree.c \
	common/pid_output.h common/error.h common/daemon.h common/log.h \
	common/server.h common/bsconv.h common/rbtree.h

CLEANFILES = *~

