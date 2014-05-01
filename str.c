/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "config.h"
#include "dns.h"
#include "dns_private.h"
#include <string.h>

/*
 * Type to string
 */
const char *
dns_type2str(uint16_t type)
{
    const char *str;

    switch ( type ) {
    case _TYPE_A:
        str = _typestr.a;
        break;
    case _TYPE_AAAA:
        str = _typestr.aaaa;
        break;
    case _TYPE_NS:
        str = _typestr.ns;
        break;
    case _TYPE_SOA:
        str = _typestr.soa;
        break;
    case _TYPE_ANY:
        str = _typestr.any;
        break;
    default:
        str = NULL;
    }

    return str;
}

/*
 * String to type
 */
uint16_t
dns_str2type(const char *str)
{
    uint16_t type;

    type = 0;
    if ( 0 == strcasecmp("A", str) ) {
        type = _TYPE_A;
    } else if ( 0 == strcasecmp("AAAA", str) ) {
        type = _TYPE_AAAA;
    } else if ( 0 == strcasecmp("NS", str) ) {
        type = _TYPE_NS;
    } else if ( 0 == strcasecmp("SOA", str) ) {
        type = _TYPE_SOA;
    } else if ( 0 == strcasecmp("ANY", str) ) {
        type = _TYPE_ANY;
    }

    return type;
}

/*
 * Class to string
 */
const char *
dns_class2str(uint16_t class)
{
    const char *str;

    switch ( class ) {
    case _CLASS_INTERNET:
        str = _classstr.internet;
        break;
    case _CLASS_ANY:
        str = _classstr.any;
        break;
    default:
        str = NULL;
    }

    return str;
}

/*
 * String to class
 */
uint16_t
dns_str2class(const char *str)
{
    uint16_t class;

    class = 0;
    if ( 0 == strcasecmp("IN", str) ) {
        class = _CLASS_INTERNET;
    } else if ( 0 == strcasecmp("ANY", str) ) {
        class = _CLASS_ANY;
    }

    return class;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
