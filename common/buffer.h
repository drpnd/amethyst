/*_
 * Copyright 2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#ifndef _UTILS_BUFFER_H
#define _UTILS_BUFFER_H

#include <stdlib.h>

struct varbuf {
    /* Buffer and length */
    unsigned char *buf;
    size_t len;

    size_t sz;
    size_t expand;

    /* Need to free? */
    int _need_to_free;
};

#ifdef __cplusplus
extern "C" {
#endif

    /* Initialize varbuf */
    struct varbuf * varbuf_init(struct varbuf *, size_t, size_t);

    /* Release varbuf */
    void varbuf_release(struct varbuf *);

    /* Append */
    int varbuf_append_char(struct varbuf *, unsigned char);

    /* Dup */
    int varbuf_dup(struct varbuf *, unsigned char **, size_t *);

#ifdef __cplusplus
}
#endif

#endif /* _UTILS_BUFFER_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
