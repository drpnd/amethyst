/*_
 * Copyright 2008 tauthon group. All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@tauthon.org>
 */

/* $Id: memory.h,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#ifndef _UTILS_MEMORY_H
#define _UTILS_MEMORY_H

#include <stddef.h>

typedef struct {
    size_t n;
    void *s;
} memory_t;

#ifdef __cplusplus
extern "C" {
#endif

    __inline__ void * memdup(const void *src, size_t sz);

#ifdef __cplusplus
}
#endif

#endif /* _UTILS_MEMORY_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
