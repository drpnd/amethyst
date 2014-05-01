/*_
 * Copyright 2009, 2011 Scyphus Solutions Co.,Ltd. All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "daemon.h"
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Daemonize the process
 */
int
daemon_ng(int nochdir, int noclose)
{
    struct sigaction osa;
    struct sigaction sa;
    int fd;
    pid_t newgrp;
    int oerrno;
    int osa_ok;

    /* A SIGHUP may be thrown when the parent exits below. */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    osa_ok = sigaction(SIGHUP, &sa, &osa);

    /* Fork and check the return value */
    switch ( fork() ) {
    case -1:
        /* Error */
        return -1;
    case 0:
        /* Continue if child */
        break;
    default:
        /* Exit if parent */
        exit(0);
    }

    /* Create new session and become the process leader */
    newgrp = setsid();
    /* Save errno */
    oerrno = errno;

    /* Recover signal handlers */
    if ( -1 != osa_ok ) {
        /* Succeeded in sigaction, then recover the SIGHUP handling  */
        sigaction(SIGHUP, &osa, NULL);
    }

    /* Check the returned value of setsid(); newgrp should same as getpid() */
    if ( -1 == newgrp ) {
        /* Setsid() failed... */
        errno = oerrno;
        return -1;
    }

    /* Fork again and check the return value */
    switch ( fork() ) {
    case -1:
        /* Error */
        return -1;
    case 0:
        /* Continue if child */
        break;
    default:
        /* Exit if parent */
        exit(0);
    }

    if ( !nochdir ) {
        /* Change directory if desired. */
        (void)chdir("/");
    }

    /* Umask */
    (void)umask((mode_t)0);

    if ( !noclose && -1 != (fd = open(_PATH_DEVNULL, O_RDWR, 0)) ) {
        /* Close stdin, stdout and stderr if desired */
        (void)dup2(fd, STDIN_FILENO);
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        if ( fd > 2 ) {
            /* If the /dev/null is not a special descriptor, then close it. */
            (void)close(fd);
        }
    }

    return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
