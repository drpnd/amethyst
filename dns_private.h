/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: dns_private.h,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#ifndef _DNS_PRIVATE_H
#define _DNS_PRIVATE_H

#include <stddef.h>

/*
 * QR (Query/Response)
 */
enum _qr {
    _QUERY = 0<<15,
    _RESPONSE = 1<<15,
};

/*
 * OPCODE
 */
enum _opcode {
    _STANDARD_QUERY = 0<<11,
    _INVERSE_QUERY = 1<<11,
    _SERVER_STATUS_REQUEST = 2<<11,
};

/*
 * Authoritative Answer
 */
enum _aa {
    _NON_AUTHORITATIVE = 0<<10,
    _AUTHORITATIVE = 1<<10,
};

/*
 * Truncation
 */
enum _tc {
    _NOT_TRUNCATED = 0<<9,
    _TRUNCATED = 1<<9,
};

/*
 * Recursion Desired
 */
enum _rd {
    _RECURSION_NOT_DESIRED = 0<<8,
    _RECURSION_DESIRED = 1<<8,
};

/*
 * Recursion Available
 */
enum _ra {
    _RECURSION_NOT_AVAILABLE = 0<<7,
    _RECURSION_AVAILABLE = 1<<7,
};

/*
 * RCODE (Response code)
 */
enum _rcode {
    _NO_ERROR = 0,
    _FORMAT_ERROR = 1,
    _SERVER_ERROR = 2,
    _NAME_ERROR = 3,
    _NOT_IMPLEMENTED = 4,
    _DENIED = 5,
};

/*
 * Query type
 */
enum _type {
    _TYPE_A = 1,
    _TYPE_NS = 2,
    _TYPE_CNAME = 5,
    _TYPE_SOA = 6,
    _TYPE_MB = 7,
    _TYPE_MG = 8,
    _TYPE_MR = 9,
    _TYPE_NULL = 10,
    _TYPE_WKS = 11,
    _TYPE_PTR = 12,
    _TYPE_HINFO = 13,
    _TYPE_MINFO = 14,
    _TYPE_MX = 15,
    _TYPE_TXT = 16,
    _TYPE_AAAA = 28,
    _TYPE_EDNS0 = 41,
    _TYPE_ANY = 255,
};
static const struct {
    const char *a;
    const char *ns;
    const char *cname;
    const char *soa;
    const char *ptr;
    const char *mx;
    const char *aaaa;
    const char *any;
} _typestr = {
    .a = "A",
    .ns = "NS",
    .cname = "CNAME",
    .soa = "SOA",
    .ptr = "PTR",
    .mx = "MX",
    .aaaa = "AAAA",
    .any = "ANY",
};


/*
 * Query class
 */
enum _class {
    _CLASS_INTERNET = 1,
    _CLASS_CSNET = 2,
    _CLASS_CHAOS = 3,
    _CLASS_HESIOD = 4,
    _CLASS_ANY = 5,
};
static const struct {
    const char *internet;
    const char *any;
} _classstr = {
    .internet = "IN",
    .any = "ANY",
};

/* Compression suffix list */
struct dns_compression_list {
    struct _comp_suffix {
        size_t ptr;
        char *str;
    } suffix;
    struct dns_compression_list *next;
};

#ifdef __cplusplus
extern "C" {
#endif

    int
    dns_build_domain(const char *, size_t, unsigned char **, size_t *,
                     struct dns_compression_list **);

    const char * dns_type2str(uint16_t);
    const char * dns_class2str(uint16_t);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_PRIVATE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
