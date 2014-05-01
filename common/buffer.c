/*_
 * Copyright 2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "buffer.h"
#include <string.h>
#include <limits.h>

/*
 * Initialize varbuf structure
 */
struct varbuf *
varbuf_init(struct varbuf *vb, size_t initsz, size_t expand)
{
    if ( NULL == vb ) {
        /* Allocate new */
        vb = malloc(sizeof(struct varbuf));
        if ( NULL == vb ) {
            /* Memory error */
            return NULL;
        }
        vb->_need_to_free = 1;
    } else {
        vb->_need_to_free = 0;
    }

    /* Allocate initial buffer */
    vb->sz = initsz;
    vb->buf = malloc(sizeof(unsigned char) * initsz);
    if ( NULL == vb->buf ) {
        if ( vb->_need_to_free ) {
            free(vb);
        }
        /* Memory error */
        return NULL;
    }

    /* Set length */
    vb->len = 0;
    vb->expand = expand;

    return vb;
}

/*
 * Release varbuf structure
 */
void
varbuf_release(struct varbuf *vb)
{
    free(vb->buf);
    if ( vb->_need_to_free ) {
        /* Free it */
        free(vb);
    }
}

/*
 * Append char
 */
int
varbuf_append_char(struct varbuf *vb, unsigned char c)
{
    unsigned char *nptr;
    size_t nsz;

    if ( vb->len >= vb->sz ) {
        /* Expand */
        if ( SIZE_T_MAX - vb->expand > vb->sz ) {
            /* Cannot expand */
            return -1;
        }
        nsz = vb->sz + vb->expand;
        nptr = realloc(vb->buf, sizeof(unsigned char) * nsz);
        if ( NULL == nptr ) {
            /* Memory error */
            return -1;
        }
        /* Set */
        vb->sz = nsz;
        vb->buf = nptr;
    }

    /* Append */
    vb->buf[vb->len] = c;
    vb->len++;

    return 0;
}

/*
 * Duplicate buffer to buf and set size to sz
 */
int
varbuf_dup(struct varbuf *vb, unsigned char **buf, size_t *sz)
{
    *sz = vb->len;
    *buf = malloc(sizeof(unsigned char) * (*sz));
    if ( NULL == *buf ) {
        /* Memory error */
        return -1;
    }

    /* Copy */
    (void)memcpy(*buf, vb->buf, *sz);

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
