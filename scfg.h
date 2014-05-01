/*_
 * Copyright 2010-2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: scfg.h,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#ifndef _SCFG_H
#define _SCFG_H

#include <stddef.h>

typedef struct _scfg scfg_t;

#ifdef __cplusplus
extern "C" {
#endif

    scfg_t * scfg_parse(const char *);
    void scfg_release(scfg_t *);

    int scfg_print(scfg_t *);

    char * scfg_get_keys(scfg_t *, const char *);
    char * scfg_get_values(scfg_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _SCFG_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
