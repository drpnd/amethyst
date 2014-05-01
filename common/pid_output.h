/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#ifndef _PID_OUTPUT_H
#define _PID_OUTPUT_H

#include "config.h"
#include <unistd.h>

#ifndef LOGFILE_MASK
#define LOGFILE_MASK 0644
#endif

#ifdef __cplusplus
extern "C" {
#endif

    pid_t pid_output(const char *);
    pid_t pid_output_read(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _PID_OUTPUT_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
