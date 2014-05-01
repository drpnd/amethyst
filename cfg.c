/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: cfg.c,v 3fd7b0a2108d 2011/02/11 09:36:32 Hirochika $ */

#include "config.h"
#include "dns.h"
#include "scfg.h"
#include "common/log.h"

#include <stdlib.h>
#include <errno.h>


/*
 * Prototype declarations
 */
static struct dns_cfg_selector *
_parse_cfg_selector(scfg_t *, char *, char *, size_t);
static struct dns_cfg_zone * _parse_cfg_zone(scfg_t *, char *);

/*
 * Parse selector configuration
 */
static struct dns_cfg_selector *
_parse_cfg_selector(scfg_t *scfg, char *selector, char *key, size_t ksz)
{
    struct dns_cfg_selector *slctr;
    char buf[256];
    const char cstype[] = "type";
    char *type;
    const char csscript[] = "script";
    char *script;

    slctr = malloc(sizeof(struct dns_cfg_selector));
    if ( NULL == slctr ) {
        return NULL;
    }

    (void)memcpy(buf, key, ksz);

    /* Get type */
    (void)memcpy(buf + ksz, cstype, sizeof(cstype));
    (void)memcpy(buf + ksz + sizeof(cstype), "", 1);
    type = scfg_get_values(scfg, buf);
    if ( NULL == type ) {
        free(slctr);
        return NULL;
    }
    if ( 0 == strcasecmp("cgi", type) ) {
        slctr->type = DNS_CFG_SELECTOR_SCRIPT;
    } else {
        free(type);
        free(slctr);
        return NULL;
    }
    free(type);

    /* Get script */
    if ( DNS_CFG_SELECTOR_SCRIPT == slctr->type ) {
        (void)memcpy(buf + ksz, csscript, sizeof(csscript));
        (void)memcpy(buf + ksz + sizeof(csscript), "", 1);
        script = scfg_get_values(scfg, buf);
        if ( NULL == script ) {
            free(slctr);
            return NULL;
        }
        slctr->target.script = script;
    } else {
        free(slctr);
        return NULL;
    }

    return slctr;
}

/*
 * Parse zone configuration
 */
static struct dns_cfg_zone *
_parse_cfg_zone(scfg_t *scfg, char *zone)
{
    char buf[256];
    struct dns_cfg_zone *zcfg;
    char *type;
    char *file;
    char *selector;

    const char cspref[] = "dns\0zone";
    const char cstype[] = "type";
    const char csfile[] = "file";
    const char csselector[] = "selector";
    size_t zonelen;

    zcfg = malloc(sizeof(struct dns_cfg_zone));
    if ( NULL == zcfg ) {
        return NULL;
    }
    zcfg->name = NULL;
    zcfg->file = NULL;
    zcfg->selector = NULL;

    /* Assign name */
    zcfg->name = strdup(zone);
    if ( NULL == zcfg->name ) {
        free(zcfg);
        return NULL;
    }

    /* Get length */
    zonelen = strlen(zone)+1;

    memcpy(buf, cspref, sizeof(cspref));
    memcpy(buf + sizeof(cspref), zone, zonelen);

    /* Get type */
    memcpy(buf + sizeof(cspref) + zonelen, cstype, sizeof(cstype));
    memcpy(buf + sizeof(cspref) + zonelen + sizeof(cstype), "", 1);
    type = scfg_get_values(scfg, buf);
    if ( NULL == type ) {
        free(zcfg->name);
        free(zcfg);
        return NULL;
    }
    if ( 0 == strcasecmp("master", type) ) {
        zcfg->type = DNS_CFG_ZONE_MASTER;
    } else if ( 0 == strcasecmp("slave", type) ) {
        zcfg->type = DNS_CFG_ZONE_SLAVE;
    } else {
        free(type);
        free(zcfg->name);
        free(zcfg);
        return NULL;
    }
    free(type);

    /* Get file */
    if ( DNS_CFG_ZONE_MASTER == zcfg->type ) {
        memcpy(buf + sizeof(cspref) + zonelen, csfile, sizeof(csfile));
        memcpy(buf + sizeof(cspref) + zonelen + sizeof(csfile), "", 1);
        file = scfg_get_values(scfg, buf);
        if ( NULL == file ) {
            free(zcfg->name);
            free(zcfg);
            return NULL;
        }
        zcfg->file = file;
    }

    /* Get selector */
    if ( DNS_CFG_ZONE_MASTER == zcfg->type ) {
        memcpy(buf + sizeof(cspref) + zonelen, csselector, sizeof(csselector));
        memcpy(buf + sizeof(cspref) + zonelen + sizeof(csselector), "", 1);
        selector = scfg_get_keys(scfg, buf);
        if ( NULL == selector ) {
            free(zcfg->file);
            free(zcfg->name);
            free(zcfg);
            return NULL;
        }
        zcfg->selector = _parse_cfg_selector(scfg, selector, buf,
                                             sizeof(cspref) + zonelen
                                             + sizeof(csselector));
        if ( NULL == zcfg->selector ) {
            free(selector);
            free(zcfg->file);
            free(zcfg->name);
            free(zcfg);
            return NULL;
        }
        free(selector);
    }

    return zcfg;
}

/*
 * Allocation new configuration instance
 */
struct dns_cfg *
dns_cfg_new(scfg_t *scfg)
{
    struct dns_cfg *dnscfg;
    char *directory;
    char *realdir;
    char *listen;
    char *zones;
    char *timeout_str;
    double timeout;
    char *selector_str;
    struct dns_cfg_selector *selector;
    char *logfile;
    struct dns_cfg_zone **zonecfgs;
    struct dns_cfg_zone *zcfg;
    char *tmp;
    char *tgt;
    int cnt;
    int ptr;

    /* Get directory */
    directory = scfg_get_values(scfg, "dns\0directory\0");
    if ( NULL == directory ) {
        goto error_out;
    }
    realdir = realpath(directory, NULL);
    if ( NULL == realdir ) {
        goto error_out1;
    }
    directory = realdir;

    /* Get listens */
    listen = scfg_get_values(scfg, "dns\0listen\0");
    if ( NULL == listen ) {
        goto error_out1;
    }

    /* Get zones */
    zones = scfg_get_keys(scfg, "dns\0zone\0");
    if ( NULL == zones && errno ) {
        goto error_out2;
    }

    zonecfgs = NULL;
    if ( zones ) {
        /* Count # of zones */
        tmp = zones;
        cnt = 0;
        while ( '\0' != *tmp ) {
            tmp += strlen(tmp) + 1;
            cnt++;
        }

        /* Allocate zone configuration */
        zonecfgs = malloc(sizeof(struct dns_cfg_zone *) * (cnt + 1));
        if ( NULL == zonecfgs ) {
            goto error_out3;
        }
        zonecfgs[cnt] = NULL;

        tmp = zones;
        ptr = 0;
        while ( '\0' != *tmp ) {
            tgt = tmp;
            tmp += strlen(tmp) + 1;

            zcfg = _parse_cfg_zone(scfg, tgt);
            if ( NULL == zcfg ) {
                goto error_out4;
            }
            zonecfgs[ptr] = zcfg;
            ptr++;
        }
    }

    /* Get timeout */
    timeout_str = scfg_get_values(scfg, "dns\0timeout\0");
    timeout = -1.0;
    if ( NULL != timeout_str ) {
        timeout = strtod(timeout_str, &tmp);
        if ( '\0' != tmp[0] ) {
            free(timeout_str);
            goto error_out4;
        } else {
            free(timeout_str);
        }
    } else if ( errno ) {
        goto error_out4;
    }

    /* Get selector */
    selector_str = scfg_get_keys(scfg, "dns\0default-selector\0");
    selector = NULL;
    if ( NULL != selector_str ) {
        selector = _parse_cfg_selector(scfg, selector_str,
                                       "dns\0default-selector\0",
                                       2 + strlen("dns")
                                       + strlen("default-selector"));
        free(selector_str);
        if ( NULL == selector ) {
            goto error_out4;
        }
    } else if ( errno ) {
        goto error_out4;
    }


    /* Get logfile */
    logfile = scfg_get_values(scfg, "dns\0logfile\0");
    if ( NULL == logfile && errno ) {
        goto error_out5;
    }

    /* Allocate dns configuration */
    dnscfg = malloc(sizeof(struct dns_cfg));
    if ( NULL == dnscfg ) {
        goto error_out6;
    }
    dnscfg->directory = directory;
    dnscfg->listens = listen;
    dnscfg->zones = zonecfgs;
    dnscfg->timeout = timeout;
    dnscfg->logfile = logfile;
    dnscfg->fbselector = selector;

    /* Free unused */
    if ( NULL != zones ) {
        free(zones);
    }

    return dnscfg;

error_out6:
    if ( NULL != logfile ) {
        free(logfile);
    }
error_out5:
    if ( NULL != selector ) {
        free(selector);
    }
error_out4:
    if ( NULL != zonecfgs ) {
        free(zonecfgs);
    }
error_out3:
    if ( NULL != zones ) {
        free(zones);
    }
error_out2:
    free(listen);
error_out1:
    free(directory);
error_out:
    return NULL;
}

/*
 * Delete a configuration instance
 */
void
dns_cfg_delete(struct dns_cfg *dnscfg)
{
    free(dnscfg->directory);
    free(dnscfg->listens);
    free(dnscfg->zones);
    if ( NULL != dnscfg->logfile ) {
        free(dnscfg->logfile);
    }
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
