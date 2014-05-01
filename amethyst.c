/*_
 * Copyright 2013 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "config.h"
#include "common/pid_output.h"
#include "common/error.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/*
 * Prototype declarations
 */
static void _usage(const char *);

/*
 * Display usage
 */
static void
_usage(const char *prog)
{
    error_quit("Usage: %s [cdnsd|chttpd] [start|stop|status]", prog);
}

/*
 * Main function
 */
int
main(int argc, const char *const argv[], const char *const envp[])
{
    pid_t pid;
    int ret;
    const char *proc;
    char *binpath;
    const char *cmd;
    char *pidfile;

    /* Check the arguments */
    if ( argc != 3 ) {
        error_quit("Usage: %s proc command", argv[0]);
    }
    proc = argv[1];
    cmd = argv[2];

    if ( 0 == strcmp(proc, "atomos") ) {
        binpath = "./atomos";
        pidfile = PATH_ATOMOS_PID;
    } else {
        _usage(argv[0]);
    }

    if ( 0 == strcmp(cmd, "start") ) {
        /* Start the specified process */
        switch ( fork() ) {
        case -1:
            /* Error */
            exit(EXIT_FAILURE);
        case 0:
            /* Child */
            ret = execl(binpath, binpath, NULL);
            if ( 0 != ret ) {
                error_quit("Cannot launch %s (%s)", proc, binpath);
            }
            break;
        default:
            /* Parent */
            (void)wait(0);
            usleep(10000);
        }

        pid = pid_output_read(pidfile);
        if ( pid >= 0 ) {
            error_msg("Started with process ID %d.", pid);
        } else {
            error_msg("Failed to launch.");
        }
    } else if ( 0 == strcmp(cmd, "status") ) {
        /* Check the process status (PID) */
        pid = pid_output_read(pidfile);
        if ( pid >= 0 ) {
            ret = kill(pid, 0);
            if ( 0 != ret ) {
                error_msg("Not running.");
                unlink(pidfile);
            } else {
                error_msg("Running with process ID %d.", pid);
            }
        } else {
            error_msg("Not running.");
        }
    } else if ( 0 == strcmp(cmd, "stop") ) {
        /* Stop the specified process */
        pid = pid_output_read(pidfile);
        if ( pid >= 0 ) {
            ret = kill(pid, SIGTERM);
            if ( 0 != ret ) {
                error_quit("Abort: Cannot terminate process %d.", pid);
            } else {
                fprintf(stderr, "Killing PID %d ", pid);
                while ( 0 == kill(pid, 0) ) {
                    fprintf(stderr, ".");
                    sleep(1);
                }
                fprintf(stderr, ". ");
                error_msg("Killed.");
                unlink(pidfile);
            }
        }
    } else if ( 0 == strcmp(cmd, "restart") ) {
        /* First stop */
        pid = pid_output_read(pidfile);
        if ( pid >= 0 ) {
            ret = kill(pid, SIGTERM);
            if ( 0 == ret ) {
                fprintf(stderr, "Killing PID %d ", pid);
                while ( 0 == kill(pid, 0) ) {
                    fprintf(stderr, ".");
                    sleep(1);
                }
                fprintf(stderr, ". ");
                error_msg("Killed.");
                unlink(pidfile);
            }
        }

        /* Then start */
        switch ( fork() ) {
        case -1:
            /* Error */
            exit(EXIT_FAILURE);
        case 0:
            /* Child */
            ret = execl(binpath, binpath, NULL);
            if ( 0 != ret ) {
                error_quit("Cannot launch %s (%s)", proc, binpath);
            }
            break;
        default:
            /* Parent */
            (void)wait(0);
            usleep(10000);
        }
        pid = pid_output_read(pidfile);
        if ( pid >= 0 ) {
            error_msg("Started with process ID %d.", pid);
        } else {
            error_msg("Failed to launch.");
        }
    } else {
        error_quit("Command not supported: %s", cmd);
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
