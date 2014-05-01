/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: zone.h,v f045f3d6e083 2011/02/12 10:50:28 Hirochika $ */

#ifndef _ZONE_H
#define _ZONE_H

#include "config.h"

#include "common/rbtree.h"

struct zone_rdata_soa {
    char *mname;
    char *rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t expire;
    uint32_t minimum;
};

struct dns_zone {
    char *name;
    struct {
        char *origin;
        uint32_t ttl;
    } directives;
};

/*
 * Zone entry
 */
struct dns_zone_entry {
    int have_zone;
    char *name;
    struct {
        size_t len;
        struct dns_zone_entry *entries;
    } children;
};

struct dns_zone_tree {
    struct dns_zone_entry *root;
};


#ifdef __cplusplus
extern "C" {
#endif

    struct dns_zone * zone_parse_file(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _ZONE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
