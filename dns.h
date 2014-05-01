/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: dns.h,v c47fcc34c973 2011/02/12 06:52:22 Hirochika $ */

#ifndef _DNS_H
#define _DNS_H

#include "scfg.h"
#include "common/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <netdb.h>
/* Socket */
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef ATOMOS_DEFAULT_USER
#define ATOMOS_DEFAULT_USER "nobody"
#endif
#ifndef AMETHYST_DEFAULT_CONFIG_FILE
#define AMETHYST_DEFAULT_CONFIG_FILE "./conf/amethyst.conf"
#endif

enum dns_cfg_selector_type {
    DNS_CFG_SELECTOR_SCRIPT,
    DNS_CFG_SELECTOR_NET,
};
enum dns_cfg_zone_type {
    DNS_CFG_ZONE_MASTER,
    DNS_CFG_ZONE_SLAVE,
};

/*
 * DNS configuration
 */
struct dns_cfg_selector {
    /* Type of selector */
    int type;
    /* Target */
    union {
        char *file;
        char *script;
        struct {
            char *host;
            char *serv;
        } net;
    } target;
};
struct dns_cfg_zone {
    /* Name of zone */
    char *name;
    /* Mater or slave */
    enum dns_cfg_zone_type type;
    /* Master/slave zone file */
    char *file;
    struct dns_cfg_selector *selector;
};
struct dns_cfg {
    /* Timeout in second */
    double timeout;
    /* Directory */
    char *directory;
    /* Listen, NULL terminated list */
    char *listens;
    /* Authoritative zones, NULL terminated list */
    struct dns_cfg_zone **zones;
    /* Default selector (for fallback) */
    struct dns_cfg_selector *fbselector;
    /* Logfile */
    char *logfile;
};

/*
 * Query and response
 */
struct dns_query {
    char name[NI_MAXHOST];
    uint16_t type;
    uint16_t class;
};
struct dns_response {
    char name[NI_MAXHOST];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    union {
        uint8_t a[4];
        uint8_t aaaa[16];
        uint8_t *cname;
        uint8_t *ns;
        struct {
            uint8_t *mname;
            uint8_t *rname;
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t minimum;
        } soa;
    } data;
};

/*
 * DNS message
 */
struct dns_message {
    uint16_t id;
    uint16_t flags;
    struct {
        uint16_t n;
        struct dns_query *c;
    } ques;
    struct {
        uint16_t n;
        struct dns_response *c;
    } ans;
    struct {
        uint16_t n;
        struct dns_response *c;
    } auth;
    struct {
        uint16_t n;
        struct dns_response *c;
    } ar;
};

/*
 * DNS daemon instance
 */
struct dns {
    char *prog;
    struct dns_cfg *cfg;
    struct log *log;
};

#ifdef __cplusplus
extern "C" {
#endif

    /* dns.c */
    struct dns_message * dns_message_new(void);
    void dns_message_delete(struct dns_message *);
    struct dns_message * dns_parse_query(const unsigned char *, size_t);
    ssize_t dns_build_response(struct dns_message *, unsigned char *, size_t);
    char * dns_printable_message(const struct dns_message *);
    size_t dns_get_payload_size(struct dns_message *);

    /* str.c */
    const char * dns_type2str(uint16_t);
    uint16_t dns_str2type(const char *);
    const char * dns_class2str(uint16_t);
    uint16_t dns_str2class(const char *);

    /* cfg.c */
    struct dns_cfg * dns_cfg_new(scfg_t *);
    void dns_cfg_delete(struct dns_cfg *);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
