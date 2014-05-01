/*_
 * Copyright 2006-2008 tauthon group. All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@tauthon.org>
 */

/* $Id: memory.c,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#include "memory.h"
#include <stdlib.h>
#include <string.h>

/*
 * Duplicate memory
 *
 * RETURN VALUE
 *      If successful, memdup() function returns a pointer to allocated memory.
 *      If there is an error, it returns a NULL pointer and set errno to ENOMEM.
 */
__inline__ void *
memdup(const void *src, size_t sz)
{
    void *ptr;

    ptr = malloc(sz);
    if ( NULL != ptr ) {
        (void) memcpy(ptr, src, sz);
    }

    return ptr;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
