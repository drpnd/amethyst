/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

struct log {
    FILE *fp;
};

#ifdef __cplusplus
extern "C" {
#endif

    struct log * log_file_open(const char *);
    int log_write(struct log *, const char *, ...);
    void log_close(struct log *);

#ifdef __cplusplus
}
#endif

#endif /* _LOG_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
