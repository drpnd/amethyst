/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#ifndef _FILE_H
#define _FILE_H

#include "config.h"
#include <unistd.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

    int file_exists(const char *);
    off_t file_detectsize(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _FILE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
