/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "config.h"
#include "time.h"
#include <time.h>
#include <sys/time.h>

/*
 * Get microtime
 */
double
microtime(void)
{
    struct timeval tv;
    int ret;

    ret = gettimeofday(&tv, NULL);
    if ( 0 != ret ) {
        return 0.0;
    }

    return tv.tv_sec + (1.0 * tv.tv_usec / 1000000);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
