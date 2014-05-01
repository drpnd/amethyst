/*_
 * Copyright 2011-2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: selector.c,v f045f3d6e083 2011/02/12 10:50:28 Hirochika $ */

#include "config.h"
#include "selector.h"
#include "dns.h"
#include "dns_private.h"
#include "common/error.h"
#include "common/rbtree.h"

#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#if TARGET_LINUX
#include <linux/limits.h>          /* For PATH_MAX */
#else
#include <sys/syslimits.h>      /* For PATH_MAX */
#endif
#include <sysexits.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <paths.h>


/*
 * Prototype declarations
 */
static __inline__ int _compare(const void *, const void *);
static int _check_zone(const char *, const char *);
static int
_call_cgi(const char *, struct dns_query *, struct dns_cfg_zone *,
          struct dns_message *, struct dns_cfg *);
static int
_call_fbcgi(const char *, struct dns_query *, struct dns_message *,
            struct dns_cfg *);
static int
_answer_to_question(const char *, struct dns_query *, struct dns_message *,
                    struct dns_cfg *);


/*
 * Compare
 */
static __inline__ int
_compare(const void *a, const void *b)
{
    return strcasecmp((const char *)a, (const char *)b);
}

/*
 * Check if the domain name is a subdomain of the zone name, i.e., *.zone
 */
static int
_check_zone(const char *zname, const char *qname)
{
    size_t nlen;
    size_t zlen;

    nlen = strlen(qname);
    zlen = strlen(zname);

    if ( 0 == strcasecmp(zname, qname) ) {
        return 1;
    } else if ( nlen > zlen ) {
        if ( '.' == qname[nlen - zlen - 1]
             && 0 == strcasecmp(zname, qname + nlen - zlen) ) {
            return 1;
        }
    }

    return 0;
}

/*
 * Call CGI
 */
static int
_call_cgi(const char *remote, struct dns_query *ques, struct dns_cfg_zone *zone,
          struct dns_message *msg, struct dns_cfg *cfg)
{
    int ret;

    /* Call CGI */
    ret = dns_selector_call_cgi(remote, ques, zone->name, msg,
                                zone->selector->target.script);
    if ( 0 != ret ) {
        if ( EX_NOHOST == ret ) {
            /* NXDOMAIN */
            return 0;
        } else {
            /* FIXME: Other errors */
            /*msg->flags &= ~_NAME_ERROR;*/
            /*msg->flags |= _SERVER_ERROR;*/
            return -1;
        }
    } else {
        msg->flags &= ~_NAME_ERROR;
        msg->flags |= _AUTHORITATIVE;
    }

    return 0;
}

/*
 * Call fallback CGI
 */
static int
_call_fbcgi(const char *remote, struct dns_query *ques, struct dns_message *msg,
            struct dns_cfg *cfg)
{
    int ret;

    /* Call CGI */
    ret = dns_selector_call_cgi(remote, ques, ".", msg,
                                cfg->fbselector->target.script);
    if ( 0 != ret ) {
        if ( EX_NOHOST == ret ) {
            /* NXDOMAIN */
            return 0;
        } else {
            /* FIXME: Other errors */
            /*msg->flags &= ~_NAME_ERROR;*/
            /*msg->flags |= _SERVER_ERROR;*/
            return -1;
        }
    } else {
        msg->flags &= ~_NAME_ERROR;
        msg->flags |= _AUTHORITATIVE;
    }

    return 0;
}

/*
 * Obtain the corresponding answers
 */
static int
_answer_to_question(const char *remote, struct dns_query *ques,
                    struct dns_message *msg, struct dns_cfg *cfg)
{
    int ret;
    struct dns_cfg_zone **zones;
    int cnt;

    cnt = 0;
    zones = cfg->zones;
    if ( zones ) {
        while ( NULL != *zones ) {
            if ( _check_zone((*zones)->name, ques->name) ) {
                /* Selector */
                if ( NULL != (*zones)->selector ) {
                    if ( DNS_CFG_SELECTOR_SCRIPT == (*zones)->selector->type ) {
                        ret = _call_cgi(remote, ques, *zones, msg, cfg);
                        if ( 0 != ret ) {
                            return -1;
                        }
                        cnt++;
                    }
                    /* FIXME */
                }
            }
            /* Next zone */
            zones++;
        }
    }
    if ( !cnt && NULL != cfg->fbselector ) {
        if ( DNS_CFG_SELECTOR_SCRIPT == cfg->fbselector->type ) {
            ret = _call_fbcgi(remote, ques, msg, cfg);
            if ( 0 != ret ) {
                return -1;
            }
            cnt++;
        }
    }

    return 0;
}

/*
 * Create a response message corresponding to the query
 */
struct dns_message *
dns_selector_query(const char *remote, const struct dns_message *query,
                   struct dns_cfg *cfg)
{
    struct dns_message *response;
    size_t qlen;
    int i;

    /* Allocate messages for response */
    response = dns_message_new();
    if ( NULL == response ) {
        /* Cannot allocate the response message */
        return NULL;
    }

    /* Copy questions */
    response->ques.n = query->ques.n;
    qlen = sizeof(struct dns_query) * query->ques.n;
    response->ques.c = malloc(qlen);
    if ( NULL == response->ques.c ) {
        /* Memory error */
        dns_message_delete(response);
        return NULL;
    }
    /* This is enough because queries do not contain any pointers. */
    (void)memcpy(response->ques.c, query->ques.c, qlen);

    /* Copy ID */
    response->id = query->id;

    /* Set flags */
    response->flags = _RESPONSE | _NAME_ERROR;

    /* Get answers for the questions */
    for ( i = 0; i < query->ques.n; i++ ) {
        if ( 0 != _answer_to_question(remote, &query->ques.c[i], response,
                                      cfg) ) {
            /* FIXME */
            /* Error on getting the corresponding answer */
            dns_message_delete(response);
            return NULL;
        }
    }

    return response;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
