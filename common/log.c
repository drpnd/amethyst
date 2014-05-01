/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */


#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <sys/file.h>

/*
 * Open log to file
 */
struct log *
log_file_open(const char *filename)
{
    struct log *log;
    FILE *fp;

    fp = fopen(filename, "a+");
    if ( NULL == fp ) {
        return NULL;
    }

    log = malloc(sizeof(struct log));
    if ( NULL == log ) {
        return NULL;
    }

    log->fp = fp;

    return log;
}

/*
 * Write log
 */
int
log_write(struct log *log, const char *fmt, ...)
{
    va_list ap;
    char buf[256];
    time_t now;
    struct tm *tm;
    int fd;

    fd = fileno(log->fp);
    (void)flock(fd, LOCK_EX);

    now = time(NULL);
    tm = localtime(&now);       /* Note: Not using gmtime here */
    (void)strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S %z]", tm);
    fprintf(log->fp, "%s ", buf);

    va_start(ap, fmt);
    vfprintf(log->fp, fmt, ap);
    va_end(ap);
    fprintf(log->fp, "\n");

    fflush(log->fp);
    (void)flock(fd, LOCK_UN);

    return 0;
}

/*
 * Close log
 */
void
log_close(struct log *log)
{
    fclose(log->fp);
    free(log);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
