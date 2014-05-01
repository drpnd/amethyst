/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: dns.c,v c47fcc34c973 2011/02/12 06:52:22 Hirochika $ */

#include "config.h"
#include "dns.h"
#include "dns_private.h"
#include "common/bsconv.h"
#include "common/error.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


#define MAX_COMPRESSION_LOOP 30
#define COMPRESS_BITS ((1<<7)|(1<<6))


/*
 * Prototype declarations
 */
static int
_parse_question(const unsigned char *, int *, int, struct dns_query *);
static int
_parse_answer(const unsigned char *, int *, int, struct dns_response *);
static int
_parse_authority(const unsigned char *, int *, int, struct dns_response *);
static int
_parse_additional(const unsigned char *, int *, int, struct dns_response *);
struct dns_compression_list *
_comp_list_add(struct dns_compression_list *, size_t , const char *);
const char *
_comp_list_search_by_pointer(struct dns_compression_list *, size_t);
static ssize_t
_comp_list_search_by_string(struct dns_compression_list *, const char *);
static void _comp_list_delete(struct dns_compression_list *);
static void _response_delete(struct dns_response);
static int _parse_domain(const unsigned char *, int *, int, char *, int, int);
static int
_parse_question(const unsigned char *, int *, int, struct dns_query *);
static ssize_t
_build_response_section(const struct dns_response *, size_t,
                        struct dns_compression_list **, unsigned char *,
                        size_t);
static int
_build_domain(const char *, size_t, unsigned char **, size_t *,
                 struct dns_compression_list **);


/*
 * Add a suffix to message compression list
 */
struct dns_compression_list *
_comp_list_add(struct dns_compression_list *r, size_t ptr, const char *str)
{
    struct dns_compression_list *e;

    e = malloc(sizeof(struct dns_compression_list));
    if ( NULL == e ) {
        return NULL;
    }
    e->suffix.ptr = ptr;
    e->suffix.str = strdup(str);
    if ( NULL == e->suffix.str ) {
        free(e);
        return NULL;
    }
    e->next = r;

    return e;
}

/*
 * Search a suffix to message compression list by pointer
 */
const char *
_comp_list_search_by_pointer(struct dns_compression_list *r, size_t ptr)
{
    while ( NULL != r ) {
        if ( r->suffix.ptr == ptr ) {
            return r->suffix.str;
        }
        r = r->next;
    }

    return NULL;
}

/*
 * Search a suffix to message compression list by string
 */
static ssize_t
_comp_list_search_by_string(struct dns_compression_list *r, const char *str)
{
    while ( NULL != r ) {

        if ( 0 == strcasecmp(r->suffix.str, str) ) {
            return r->suffix.ptr;
        }
        r = r->next;
    }

    return -1;
}

/*
 * delete message compression list
 */
static void
_comp_list_delete(struct dns_compression_list *root)
{
    if ( NULL != root ) {
        _comp_list_delete(root->next);
        free(root->suffix.str);
        free(root);
    }
}

/*
 * Allocate new DNS message
 */
struct dns_message *
dns_message_new(void)
{
    struct dns_message *msg;

    msg = malloc(sizeof(struct dns_message));
    if ( NULL == msg ) {
        /* Memory error */
        return NULL;
    }
    msg->id = 0;
    msg->flags = 0;
    msg->ques.n = 0;
    msg->ques.c = NULL;
    msg->ans.n = 0;
    msg->ans.c = NULL;
    msg->auth.n = 0;
    msg->auth.c = NULL;
    msg->ar.n = 0;
    msg->ar.c = NULL;

    return msg;
}

/*
 * Delete DNS message
 */
void
dns_message_delete(struct dns_message *msg)
{
    int i;

    if ( NULL != msg->ques.c ) {
        free(msg->ques.c);
    }
    if ( NULL != msg->ans.c ) {
        for ( i = 0; i < msg->ans.n; i++ ) {
            _response_delete(msg->ans.c[i]);
        }
        free(msg->ans.c);
    }
    if ( NULL != msg->auth.c ) {
        for ( i = 0; i < msg->auth.n; i++ ) {
            _response_delete(msg->auth.c[i]);
        }
        free(msg->auth.c);
    }
    if ( NULL != msg->ar.c ) {
        for ( i = 0; i < msg->ar.n; i++ ) {
            _response_delete(msg->ar.c[i]);
        }
        free(msg->ar.c);
    }
    free(msg);
}

/*
 * Delete a repsponse
 */
static void
_response_delete(struct dns_response r)
{
    if ( _TYPE_NS == r.type ) {
        if ( NULL != r.data.ns ) {
            free(r.data.ns);
        }
    } else if ( _TYPE_CNAME == r.type ) {
        if ( NULL != r.data.cname ) {
            free(r.data.cname);
        }
    } else if ( _TYPE_SOA == r.type ) {
        if ( NULL != r.data.soa.mname ) {
            free(r.data.soa.mname);
        }
        if ( NULL != r.data.soa.rname ) {
            free(r.data.soa.rname);
        }
    }
}

/*
 * Parse returned domain name
 */
static int
_parse_domain(const unsigned char *buf, int *ptr, int n, char *host,
              int hostlen, int depth)
{
    int tmp_ptr;
    int cptr;
    int ret;
    int len;
    int blen;

    /* Increase depth */
    depth++;

    /* Check the depth */
    if ( depth > MAX_COMPRESSION_LOOP ) {
        return -1;
    }

    /* Set current pointer */
    cptr = *ptr;
    /* Set zero to length  */
    len = 0;

    /* To the end of data */
    for ( ;; ) {
        /* Check compression */
        if ( COMPRESS_BITS == (COMPRESS_BITS & (unsigned int)buf[cptr]) ) {
            /* Check overflow */
            if ( cptr + 1 >= n ) {
                /*cptr+2 >= n ???*/
                /* Overflow */
                return -1;
            }
            /* Compressed */
            tmp_ptr = bs2uint16(buf+cptr, BSCONV_ENDIAN_NETWORK);
            tmp_ptr = tmp_ptr ^ (COMPRESS_BITS<<8);
            cptr += 2;
            /* Recursive parse */
            ret = _parse_domain(
                buf, &tmp_ptr, n, host + len, hostlen - len, depth);
            if ( ret < 0 ) {
                /* Error */
                return -1;
            }
            len += ret;
            break;
        } else {
            /* Not compressed */
            blen = (unsigned int)buf[cptr];
            if ( cptr + blen + 1 >= n ) {
                /* Read buffer overflow */
                return -1;
            }
            /* Check buffer overflow */
            if ( len + blen + 2 >= hostlen ) {
                /* Buffer (for write) overflow */
                return -1;
            }
            /* Write to buffer */
            if ( blen > 0 ) {
                (void)memcpy(host+len, buf+cptr+1, blen);
            }
            /* Increase written length */
            len += blen + 1;
            /* Increase current pointer */
            cptr += blen + 1;
            /* Add dot */
            host[len-1] = '.';
            /* Add string terminate */
            host[len] = '\0';
            /* Check the end of string */
            if ( 0 == blen ) {
                break;
            } else if ( 0 == buf[cptr] ) {
                cptr += 1;
                break;
            }
        }
    }

    /* Set the pointer */
    *ptr = cptr;

    return len;
}

/*
 * Parse DNS query
 */
struct dns_message *
dns_parse_query(const unsigned char *buf, size_t n)
{
    struct dns_message *msg;
    int len;
    int i;
    int ret;

    /* Allocate */
    msg = dns_message_new();
    if ( NULL == msg ) {
        return NULL;
    }

    len = 0;

    /* Buf should not be less than 12. */
    if ( n < 12 ) {
        free(msg);
        return NULL;
    }

    /* ID */
    msg->id = bs2uint16(buf + len, BSCONV_ENDIAN_NETWORK);
    len += 2;

    /* Flags */
    msg->flags = bs2uint16(buf + len, BSCONV_ENDIAN_NETWORK);
    len += 2;

    /* # of req */
    msg->ques.n = bs2uint16(buf + len, BSCONV_ENDIAN_NETWORK);
    len += 2;

    /* # of res */
    msg->ans.n = bs2uint16(buf + len, BSCONV_ENDIAN_NETWORK);
    len += 2;

    /* # of AAs */
    msg->auth.n = bs2uint16(buf + len, BSCONV_ENDIAN_NETWORK);
    len += 2;

    /* # of ARs */
    msg->ar.n = bs2uint16(buf + len, BSCONV_ENDIAN_NETWORK);
    len += 2;

    /* Allocate request list */
    if ( msg->ques.n > 0 ) {
        msg->ques.c = malloc(sizeof(struct dns_query) * msg->ques.n);
        if ( NULL == msg->ques.c ) {
            free(msg);
            return NULL;
        }
    }
    if ( msg->ans.n > 0 ) {
        msg->ans.c = malloc(sizeof(struct dns_response) * msg->ans.n);
        if ( NULL == msg->ans.c ) {
            free(msg->ques.c);
            free(msg);
            return NULL;
        }
    }
    if ( msg->auth.n > 0 ) {
        msg->auth.c = malloc(sizeof(struct dns_response) * msg->auth.n);
        if ( NULL == msg->auth.c ) {
            free(msg->ques.c);
            free(msg->ans.c);
            free(msg);
            return NULL;
        }
    }
    if ( msg->ar.n > 0 ) {
        msg->ar.c = malloc(sizeof(struct dns_response) * msg->ar.n);
        if ( NULL == msg->ar.c ) {
            free(msg->ques.c);
            free(msg->ans.c);
            free(msg->auth.c);
            free(msg);
            return NULL;
        }
    }

    /* Query */
    for ( i = 0; i < msg->ques.n; i++ ) {
        ret = _parse_question(buf, &len, n, &msg->ques.c[i]);
        if ( ret < 0 ) {
            /* Error */
            dns_message_delete(msg);
            return NULL;
        }
    }

    /* Answer */
    for ( i = 0; i < msg->ans.n; i++ ) {
        ret = _parse_answer(buf, &len, n, &msg->ans.c[i]);
        if ( ret < 0 ) {
            /* Error */
            dns_message_delete(msg);
            return NULL;
        }
    }

    /* AAs */
    for ( i = 0; i < msg->auth.n; i++ ) {
        ret = _parse_authority(buf, &len, n, &msg->auth.c[i]);
        if ( ret < 0 ) {
            /* Error */
            dns_message_delete(msg);
            return NULL;
        }
    }

    /* ARs */
    for ( i = 0; i < msg->ar.n; i++ ) {
        ret = _parse_additional(buf, &len, n, &msg->ar.c[i]);
        if ( ret < 0 ) {
            /* Error */
            dns_message_delete(msg);
            return NULL;
        }
    }

    return msg;
}

/*
 * Parse question record
 */
static int
_parse_question(const unsigned char *buf, int *ptr, int n,
                struct dns_query *ques)
{
    int ret;

    /* Name */
    ret = _parse_domain(buf, ptr, n, ques->name, sizeof(ques->name), 0);
    if ( ret < 0 ) {
        return -1;
    }

    /* Check length */
    if ( *ptr + 4 > n ) {
        return -1;
    }

    /* type */
    ques->type = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* class */
    ques->class = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    return 0;
}

/*
 * Parse answer section
 */
static int
_parse_answer(const unsigned char *buf, int *ptr, int n,
              struct dns_response *res)
{
    int ret;
    uint16_t dlen;

    /* Name */
    ret = _parse_domain(buf, ptr, n, res->name, sizeof(res->name), 0);
    if ( ret < 0 ) {
        return -1;
    }

    /* Check length */
    if ( *ptr + 10 > n ) {
        return -1;
    }

    /* Type */
    res->type = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* Class */
    res->class = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* TTL */
    res->ttl = bs2uint32(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 4;

    /* DLEN */
    dlen = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* FIXME: Parse it!  */
    if ( *ptr + dlen > n ) {
        return -1;
    }
    *ptr += dlen;

    return 0;
}

/*
 * Parse authority section
 */
static int
_parse_authority(const unsigned char *buf, int *ptr, int n,
                 struct dns_response *res)
{
    int ret;
    uint16_t dlen;

    /* Name */
    ret = _parse_domain(buf, ptr, n, res->name, sizeof(res->name), 0);
    if ( ret < 0 ) {
        return -1;
    }

    /* Check length */
    if ( *ptr + 10 > n ) {
        return -1;
    }

    /* Type */
    res->type = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* Class */
    res->class = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* TTL */
    res->ttl = bs2uint32(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 4;

    /* DLEN */
    dlen = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* FIXME: Parse it!  */
    if ( *ptr + dlen > n ) {
        return -1;
    }
    *ptr += dlen;

    return 0;
}

/*
 * Parse additional answers
 */
static int
_parse_additional(const unsigned char *buf, int *ptr, int n,
                  struct dns_response *res)
{
    int ret;
    uint16_t dlen;

    /* Name */
    ret = _parse_domain(buf, ptr, n, res->name, sizeof(res->name), 0);
    if ( ret < 0 ) {
        return -1;
    }

    /* Check length */
    if ( *ptr + 10 > n ) {
        return -1;
    }

    /* Type */
    res->type = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* Class */
    res->class = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* TTL */
    res->ttl = bs2uint32(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 4;

    /* DLEN */
    dlen = bs2uint16(buf + *ptr, BSCONV_ENDIAN_NETWORK);
    *ptr += 2;

    /* FIXME: Parse it!  */
    if ( *ptr + dlen > n ) {
        return -1;
    }
    *ptr += dlen;

    return 0;
}

/*
 * Build domain
 */
static int
_build_domain(const char *name, size_t base, unsigned char **bname,
              size_t *bsize, struct dns_compression_list **clist)
{
    int len;
    int i;
    int sptr;
    uint16_t cptr;
    int found;
    int flag;
    ssize_t ptr;
    struct dns_compression_list *tlist;

    /* . */
    if ( 0 == strcmp(".", name) ) {
        *bsize = 1;
        *bname = malloc(sizeof(unsigned char) * (*bsize));
        if ( NULL == *bname ) {
            /* Memory error */
            return -1;
        }
        (*bname)[0] = 0;
        return 0;
    }

    len = strlen(name);
    /* Check whether the name ends with . */
    if ( '.' != name[len-1] ) {
        /* FIXME */
        error_warn("%s does not end with '.'.", name);
    }

    /* Preprocess */
    flag = 1;
    /* Loop */
    found = -1;
    for ( i = 0; i < len; i++ ) {
        if ( flag ) {
            /* Check compression ability */
            ptr = _comp_list_search_by_string(*clist, name+i);
            if ( ptr >= 0 ) {
                /* Found */
                found = i;
                break;
            } else {
                /* Not found */
                tlist = _comp_list_add(*clist, base + i, name+i);
                if ( NULL == tlist ) {
                    return -1;
                }
                *clist = tlist;
            }
        }

        /* Split */
        if ( '.' == name[i] ) {
            flag = 1;
        } else {
            flag = 0;
        }
    }
    if ( found >= 0 ) {
        /* Found then compress */
        *bsize = found + 2;
        *bname = malloc(sizeof(unsigned char) * (*bsize));
        if ( NULL == *bname ) {
            /* Memory error */
            return -1;
        }
        sptr = 0;
        for ( i = 0; i < found; i++ ) {
            if ( '.' != name[i] ) {
                (*bname)[i+1] = name[i];
            } else {
                (*bname)[sptr] = i - sptr;
                sptr = i + 1;
            }
        }
        cptr = htons((COMPRESS_BITS<<8) | ptr);
        (void)memcpy((*bname)+found, &cptr, 2);
    } else {
        /* No compression */
        *bsize = len + 1;
        *bname = malloc(sizeof(unsigned char) * (*bsize));
        if ( NULL == *bname ) {
            /* Memory error */
            return -1;
        }
        sptr = 0;
        for ( i = 0; i < len; i++ ) {
            if ( '.' != name[i] ) {
                (*bname)[i+1] = name[i];
            } else {
                (*bname)[sptr] = i - sptr;
                sptr = i + 1;
            }
        }
        (*bname)[len] = 0;
    }

    return 0;
}

/*
 * Build response section
 *      Note: Need to be shaped up...
 */
static ssize_t
_build_response_section(const struct dns_response *r, size_t base,
                        struct dns_compression_list **clist,
                        unsigned char *buf, size_t bsize)
{
    uint16_t b16;
    uint32_t b32;
    unsigned char *nmstr;
    unsigned char *nmstr2;
    size_t nmlen;
    size_t nmlen2;
    size_t len;

    /* Set base position */
    len = base;

    /* Name */
    if ( 0 != _build_domain(r->name, (size_t)len, &nmstr, &nmlen, clist) ) {
        return -1;
    }
    /* Length check */
    if ( bsize < len + nmlen + 10 ) {
        free(nmstr);
        return -1;
    }
    /* Set this */
    (void)memcpy(buf + len, nmstr, nmlen);
    len += nmlen;
    /* Free */
    free(nmstr);

    /* Query type */
    b16 = htons(r->type);
    (void)memcpy(buf + len, &b16, 2);
    len += 2;

    /* Query class */
    b16 = htons(r->class);
    (void)memcpy(buf + len, &b16, 2);
    len += 2;

    /* TTL */
    b32 = htonl(r->ttl);
    (void)memcpy(buf + len, &b32, 4);
    len += 4;

    if ( r->type == _TYPE_NS ) {
        /* Data */
        if ( 0 != _build_domain((char *)r->data.ns, (size_t)len+2, &nmstr,
                                &nmlen, clist) ) {
            return -1;
        }
        /* Data length */
        b16 = htons(nmlen);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;
        /* Length check */
        if ( bsize < len + nmlen ) {
            free(nmstr);
            return -1;
        }
        /* Set this */
        (void)memcpy(buf + len, nmstr, nmlen);
        len += nmlen;
        /* Free */
        free(nmstr);
    } else if ( r->type == _TYPE_A )  {
        /* Length check */
        if ( bsize < len + 6 ) {
            return -1;
        }

        /* Data length */
        b16 = htons(4);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;

        /* Data */
        (void)memcpy(buf + len, r->data.a, 4);
        len += 4;
    } else if ( r->type == _TYPE_AAAA ) {
        /* Length check */
        if ( bsize < len + 18 ) {
            return -1;
        }

        /* Data length */
        b16 = htons(16);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;

        /* Data */
        (void)memcpy(buf + len, r->data.aaaa, 16);
        len += 16;
    } else if ( r->type == _TYPE_CNAME ) {
        /* Data */
        if ( 0 != _build_domain((char *)r->data.cname, (size_t)len+2, &nmstr,
                                &nmlen, clist) ) {
            return -1;
        }
        /* Data length */
        b16 = htons(nmlen);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;
        /* Length check */
        if ( bsize < len + nmlen ) {
            free(nmstr);
            return -1;
        }
        /* Set this */
        (void)memcpy(buf + len, nmstr, nmlen);
        len += nmlen;
        /* Free */
        free(nmstr);
    } else if ( r->type == _TYPE_SOA ) {
        /* MNAME */
        if ( 0 != _build_domain((char *)r->data.soa.mname, (size_t)len+2,
                                &nmstr, &nmlen, clist) ) {
            return -1;
        }
        /* RNAME */
        if ( 0 != _build_domain((char *)r->data.soa.rname, (size_t)len+nmlen+2,
                                &nmstr2, &nmlen2, clist) ) {
            free(nmstr);
            return -1;
        }

        /* Data length */
        b16 = htons(nmlen + nmlen2 + 20);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;
        /* Length check */
        if ( bsize < len + nmlen + nmlen2 + 20 ) {
            free(nmstr);
            free(nmstr2);
            return -1;
        }
        /* Set MNAME and RNAME */
        (void)memcpy(buf + len, nmstr, nmlen);
        len += nmlen;
        (void)memcpy(buf + len, nmstr2, nmlen2);
        len += nmlen2;
        /* Free */
        free(nmstr);
        free(nmstr2);

        /* Set serial */
        b32 = htonl(r->data.soa.serial);
        (void)memcpy(buf + len, &b32, 4);
        len += 4;

        /* Set refresh */
        b32 = htonl(r->data.soa.refresh);
        (void)memcpy(buf + len, &b32, 4);
        len += 4;

        /* Set retry */
        b32 = htonl(r->data.soa.retry);
        (void)memcpy(buf + len, &b32, 4);
        len += 4;

        /* Set expire */
        b32 = htonl(r->data.soa.expire);
        (void)memcpy(buf + len, &b32, 4);
        len += 4;

        /* Set minimum */
        b32 = htonl(r->data.soa.minimum);
        (void)memcpy(buf + len, &b32, 4);
        len += 4;
    } else {
        /* FIXME: To implemenent other types */
        return -1;
    }

    return len - base;
}

/*
 * Build response
 *      FIXME: EDNS0/truncate error support
 */
ssize_t
dns_build_response(struct dns_message *msg, unsigned char *buf, size_t bsize)
{
    uint16_t b16;
    size_t len;
    unsigned char *nmstr;
    size_t nmlen;
    ssize_t ret;
    struct dns_compression_list *clist;
    int i;

    clist = NULL;

    /* Reset the length */
    len = 0;

    /* Length check */
    if ( bsize < 6 ) {
        return -1;
    }

    /* ID */
    b16 = htons(msg->id);
    (void)memcpy(buf+len, &b16, 2);
    len += 2;

    /* Flags |_NAME_ERROR */
    b16 = htons(msg->flags);
    (void)memcpy(buf+len, &b16, 2);
    len += 2;

    /* # of questions */
    b16 = htons(msg->ques.n);
    (void)memcpy(buf+len, &b16, 2);
    len += 2;

    /* # of answer section records */
    b16 = htons(msg->ans.n);
    (void)memcpy(buf+len, &b16, 2);
    len += 2;

    /* # of authority records */
    b16 = htons(msg->auth.n);
    (void)memcpy(buf+len, &b16, 2);
    len += 2;

    /* # of additional records */
    b16 = htons(msg->ar.n);
    (void)memcpy(buf+len, &b16, 2);
    len += 2;

    /* Build question */
    for ( i = 0; i < msg->ques.n; i++ ) {
        if ( 0 != _build_domain(msg->ques.c[i].name, (size_t)len, &nmstr,
                                &nmlen, &clist) ) {
            _comp_list_delete(clist);
            clist = NULL;
            return -1;
        }
        /* Length check */
        if ( bsize < len + nmlen + 4 ) {
            free(nmstr);
            _comp_list_delete(clist);
            clist = NULL;
            return -1;
        }
        /* Set this */
        (void)memcpy(buf+len, nmstr, nmlen);
        len += nmlen;
        /* Free */
        free(nmstr);

        /* Query type */
        b16 = htons(msg->ques.c[i].type);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;

        /* Query class */
        b16 = htons(msg->ques.c[i].class);
        (void)memcpy(buf + len, &b16, 2);
        len += 2;
    }

    /* Build answer section */
    for ( i = 0; i < msg->ans.n; i++ ) {
        ret = _build_response_section(&msg->ans.c[i], len, &clist, buf, bsize);
        if ( ret < 0 ) {
            _comp_list_delete(clist);
            clist = NULL;
            /* FIXME? */
            return -1;
        }
        len += ret;
    }

    /* Build authority section */
    for ( i = 0; i < msg->auth.n; i++ ) {
        ret = _build_response_section(&msg->auth.c[i], len, &clist, buf, bsize);
        if ( ret < 0 ) {
            _comp_list_delete(clist);
            clist = NULL;
            /* Return partial results */
            return len;
        }
        len += ret;
    }

    /* Build additional records */
    for ( i = 0; i < msg->ar.n; i++ ) {
        ret = _build_response_section(&msg->ar.c[i], len, &clist, buf, bsize);
        if ( ret < 0 ) {
            _comp_list_delete(clist);
            clist = NULL;
            /* Return partial results */
            return len;
        }
        len += ret;
    }

    _comp_list_delete(clist);
    clist = NULL;

    return len;
}

/*
 * Build printable message
 */
char *
dns_printable_message(const struct dns_message *msg)
{
    size_t len;
    int i;
    char buf[4096];
    char tmpbuf[512];
    char *nstr;

    snprintf(buf, sizeof(buf), "ID:%u; Flags:0x%x; ", msg->id, msg->flags);
    len = strlen(buf);

    /* Build question */
    snprintf(buf+len, sizeof(buf)-len, "Q:");
    len = strlen(buf);
    for ( i = 0; i < msg->ques.n; i++ ) {
        if ( i > 0 ) {
            snprintf(buf+len, sizeof(buf)-len, ",");
            len = strlen(buf);
        }
        snprintf(buf+len, sizeof(buf)-len, "[%s %s %s]", msg->ques.c[i].name,
                 dns_type2str(msg->ques.c[i].type),
                 dns_class2str(msg->ques.c[i].class));
        len = strlen(buf);
    }
    snprintf(buf+len, sizeof(buf)-len, "; ");
    len = strlen(buf);

    /* Build answer section */
    snprintf(buf+len, sizeof(buf)-len, "A:");
    len = strlen(buf);
    for ( i = 0; i < msg->ans.n; i++ ) {
        if ( i > 0 ) {
            snprintf(buf+len, sizeof(buf)-len, ",");
            len = strlen(buf);
        }

        switch ( msg->ans.c[i].type ) {
        case _TYPE_A:
            inet_ntop(AF_INET, msg->ans.c[i].data.a, tmpbuf,
                      sizeof(tmpbuf));
            break;
        case _TYPE_AAAA:
            inet_ntop(AF_INET6, msg->ans.c[i].data.aaaa, tmpbuf,
                      sizeof(tmpbuf));
            break;
        case _TYPE_NS:
            snprintf(tmpbuf, sizeof(tmpbuf), "%s", msg->ans.c[i].data.ns);
            break;
        case _TYPE_CNAME:
            snprintf(tmpbuf, sizeof(tmpbuf), "%s",
                     msg->ans.c[i].data.cname);
            break;
        case _TYPE_SOA:
            snprintf(tmpbuf, sizeof(tmpbuf), "%s %s %u %u %u %u %u",
                     msg->ans.c[i].data.soa.rname,
                     msg->ans.c[i].data.soa.mname,
                     msg->ans.c[i].data.soa.serial,
                     msg->ans.c[i].data.soa.refresh,
                     msg->ans.c[i].data.soa.retry,
                     msg->ans.c[i].data.soa.expire,
                     msg->ans.c[i].data.soa.minimum);
            break;
        default:
            tmpbuf[0] = '\0';
        }

        snprintf(buf+len, sizeof(buf)-len, "[%s %s %s %d %s]",
                 msg->ans.c[i].name, dns_type2str(msg->ans.c[i].type),
                 dns_class2str(msg->ans.c[i].class), msg->ans.c[i].ttl,
                 tmpbuf);
        len = strlen(buf);
    }
    snprintf(buf+len, sizeof(buf)-len, ";");
    len = strlen(buf);

#if 0
    /* Build authority section */
    for ( i = 0; i < msg->auth.n; i++ ) {
    }

    /* Build additional records */
    for ( i = 0; i < msg->ar.n; i++ ) {
    }
#endif

    nstr = strdup(buf);
    return nstr;
}

/*
 * Get UDP payload size
 */
size_t
dns_get_payload_size(struct dns_message *msg)
{
    size_t size;
    int i;

    /* Search EDNS0 option */
    size = 512;
    for ( i = 0; i < msg->ar.n; i++ ) {
        if ( 0 == strcmp(".", msg->ar.c[i].name)
             && 0x0029 == msg->ar.c[i].type ) {
            size = msg->ar.c[i].class;
        }
    }

    return size;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
