/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: selector.h,v f045f3d6e083 2011/02/12 10:50:28 Hirochika $ */

#ifndef _DNS_SELECTOR_H
#define _DNS_SELECTOR_H

#include "config.h"
#include "dns.h"

#if 0
struct dns_selector {
    void *dummy;
};
#endif

#ifdef __cplusplus
extern "C" {
#endif

    struct dns_message *
    dns_selector_query(const char *, const struct dns_message *,
                       struct dns_cfg *);
    int
    dns_selector_call_cgi(const char *, struct dns_query *, char *,
                          struct dns_message *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_SELECTOR_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
