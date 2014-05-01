/*_
 * Copyright 2011-2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "config.h"
#include "selector.h"
#include "dns.h"
#include "dns_private.h"
#include "common/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <sysexits.h>
#include <ctype.h>
#include <signal.h>
#include <arpa/inet.h>

/*
 * Declaration of static functions
 */
static int _ipv6_str2bin(char *, uint8_t *);
static char * _mem2asciz(const unsigned char *, size_t);
//static int _parse_line(const unsigned char *, size_t);
static int
_parse_cgi_output(const unsigned char *, size_t, struct dns_message *);

/*
 * IPv6 string format to binary
 */
static int
_ipv6_str2bin(char *ipaddr, uint8_t *data)
{
    return inet_pton(AF_INET6, ipaddr, data);
}

/*
 * Convert binary data to asciz, terminated by '\0'.
 */
static char *
_mem2asciz(const unsigned char *s, size_t n)
{
    char *str;
    int i;
    int ptr;

    /* Allocate memory for the returned value */
    str = malloc(sizeof(char) * (n + 1));
    if ( NULL == str ) {
        /* Memory error */
        return NULL;
    }

    /* Copy string */
    for ( i = 0, ptr = 0; i < n; i++ ) {
        if ( 0 != s[i] && isascii(s[i]) ) {
            str[ptr] = s[i];
            ptr++;
        }
    }
    /* Terminated by '\0' */
    str[ptr] = '\0';

    return str;
}

/*
 * Parse line
 */
static int
_parse_line(char *s, struct dns_response **tresc, uint16_t *tresn)
{
    char datpat[1024];
    char name[NI_MAXHOST];
    char type[16];
    char class[16];
    char soa_mname[NI_MAXHOST];
    char soa_rname[NI_MAXHOST];
    uint32_t soa_serial;
    uint32_t soa_refresh;
    uint32_t soa_retry;
    uint32_t soa_expire;
    uint32_t soa_minimum;
    uint32_t ttl;
    char ans[4096];
    char *bstr;
    int fn;
    int d[4];
    uint8_t d6[16];
    int i;
    int ret;

    fn = 0;
    bstr = s;
    while ( '\0' != *s && '\n' != *s ) {
        if ( ' ' == *s ) {
            switch ( fn ) {
            case 0:
                /* Name */
                /* Check the length first */
                if ( s - bstr >= sizeof(name) ) {
                    /* Too long name */
                    error_warn("The called CGI script returned too long name.");
                    return EX_DATAERR;
                }
                /* Copy */
                if ( s - bstr > 0 ) {
                    (void)memcpy(name, bstr, s - bstr);
                }
                name[s-bstr] = '\0';
                bstr = s + 1;
                fn++;
                break;
            case 1:
                /* Type */
                /* Check the length first */
                if ( s - bstr >= sizeof(type) ) {
                    /* Too long name */
                    error_warn("The called CGI script returned too long type.");
                    return EX_DATAERR;
                }
                /* Copy */
                if ( s - bstr > 0 ) {
                    (void)memcpy(type, bstr, s - bstr);
                }
                type[s-bstr] = '\0';
                bstr = s + 1;
                fn++;
                break;
            case 2:
                /* Class */
                /* Check the length first */
                if ( s - bstr >= sizeof(class) ) {
                    /* Too long name */
                    error_warn("The called CGI script returned too long"
                               "class.");
                    return EX_DATAERR;
                }
                /* Copy */
                if ( s - bstr > 0 ) {
                    (void)memcpy(class, bstr, s - bstr);
                }
                class[s-bstr] = '\0';
                bstr = s + 1;
                fn++;
                break;
            case 3:
                /* TTL */
                /* Parse 16bit TTL */
                ttl = strtol(bstr, NULL, 10);
                bstr = s + 1;
                fn++;
                break;
            default:
                /* Nothing to do */
                ;
            }
        }
        s++;
    }
    if ( fn < 4 ) {
        /* Invalid format */
        error_warn("The called CGI script returned invalid output.");
        return EX_DATAERR;
    }
    /* Answer */
    /* Check the length first */
    if ( s - bstr >= sizeof(ans) ) {
        /* Too long name */
        error_warn("The called CGI script returned too long answer.");
        return EX_DATAERR;
    }
    /* Copy */
    if ( s - bstr > 0 ) {
        (void)memcpy(ans, bstr, s - bstr);
    }
    ans[s-bstr] = '\0';


    /* Copy to the response structure */
    /* Name */
    (void)strncpy((*tresc)[*tresn].name, name, sizeof((*tresc)[*tresn].name));
    /* Type */
    (*tresc)[*tresn].type = dns_str2type(type);
    /* Class */
    (*tresc)[*tresn].class = dns_str2class(class);
    /* TTL */
    (*tresc)[*tresn].ttl = ttl;
    /* Parse data */
    if ( _TYPE_A == (*tresc)[*tresn].type ) {
        sscanf(ans, "%d.%d.%d.%d", &d[0], &d[1], &d[2], &d[3]);
        (*tresc)[*tresn].data.a[0] = d[0];
        (*tresc)[*tresn].data.a[1] = d[1];
        (*tresc)[*tresn].data.a[2] = d[2];
        (*tresc)[*tresn].data.a[3] = d[3];
    } else if ( _TYPE_AAAA == (*tresc)[*tresn].type ) {
        _ipv6_str2bin(ans, d6);
        for ( i = 0; i < 16; i++ ) {
            (*tresc)[*tresn].data.aaaa[i] = d6[i];
        }
    } else if ( _TYPE_NS == (*tresc)[*tresn].type ) {
        (*tresc)[*tresn].data.ns = (void *)strdup(ans);
        if ( NULL == (*tresc)[*tresn].data.ns ) {
            /* Memory error */
            return EX_SOFTWARE;
        }
    } else if ( _TYPE_CNAME == (*tresc)[*tresn].type ) {
        (*tresc)[*tresn].data.cname = (void *)strdup(ans);
        if ( NULL == (*tresc)[*tresn].data.cname ) {
            /* Memory error */
            return EX_SOFTWARE;
        }
    } else if ( _TYPE_SOA == (*tresc)[*tresn].type ) {
        (void)snprintf(datpat, sizeof(datpat),
                       "%%%ds %%%ds %%u %%u %%u %%u %%u", NI_MAXHOST - 1,
                       NI_MAXHOST - 1);
        ret = sscanf(ans, datpat, soa_mname, soa_rname, &soa_serial,
                     &soa_refresh, &soa_retry, &soa_expire, &soa_minimum);
        if ( 7 != ret ) {
            /* Invalid data */
            error_warn("The called CGI script returned invalid SOA record.");
            return EX_DATAERR;
        }
        (*tresc)[*tresn].data.soa.mname = (void *)strdup(soa_mname);
        if ( NULL == (*tresc)[*tresn].data.soa.mname ) {
            /* Memory error */
            return EX_SOFTWARE;
        }
        (*tresc)[*tresn].data.soa.rname = (void *)strdup(soa_rname);
        if ( NULL == (*tresc)[*tresn].data.soa.rname ) {
            /* Memory error */
            free((*tresc)[*tresn].data.soa.mname);
            return EX_SOFTWARE;
        }
        (*tresc)[*tresn].data.soa.serial = soa_serial;
        (*tresc)[*tresn].data.soa.refresh = soa_refresh;
        (*tresc)[*tresn].data.soa.retry = soa_retry;
        (*tresc)[*tresn].data.soa.expire = soa_expire;
        (*tresc)[*tresn].data.soa.minimum = soa_minimum;
    } else {
        /* FIXME */
        return EX_DATAERR;
    }

    return 0;
}

/*
 * Parse CGI output
 */
static int
_parse_cgi_output(const unsigned char *s, size_t n, struct dns_message *msg)
{
    char *input;
    char *tmp;
    int ret;
    struct dns_response **tresc;
    uint16_t *tresn;
    struct dns_response *nres;
    int sectype = 0;


    /* Convert to asciz */
    input = _mem2asciz(s, n);
    if ( NULL == input ) {
        /* Memory error */
        return EX_UNAVAILABLE;
    }
    tmp = input;
    /* Skip white spaces */
    while ( isspace(*tmp) ) {
        if ( '\n' == *tmp ) {
            sectype++;
        }
        tmp++;
    }
    /* Parse until the end */
    while ( '\0' != *tmp ) {
        /* Check the type of current section */
        switch ( sectype ) {
        case 0:
            /* Answer section */
            tresc = &(msg->ans.c);
            tresn = &(msg->ans.n);
            break;
        case 1:
            /* Authority section */
            tresc = &(msg->auth.c);
            tresn = &(msg->auth.n);
            break;
        default:
            /* Additional record */
            tresc = &(msg->ar.c);
            tresn = &(msg->ar.n);
            break;
        }

        /* Allocate a response record */
        nres = realloc(*tresc, sizeof(struct dns_response) * (*tresn + 1));
        if ( NULL == nres ) {
            /* Memory error */
            free(input);
            return EX_SOFTWARE;
        }
        *tresc = nres;

        ret = _parse_line(tmp, tresc, tresn);
        if ( 0 != ret ) {
            free(input);
            return ret;
        }

        (*tresn)++;

        /* Skip until the end-of-line */
        while ( '\n' != *tmp && '\0' != *tmp ) {
            tmp++;
        }
        /* Skip white spaces */
        sectype--;
        while ( isspace(*tmp) ) {
            if ( '\n' == *tmp ) {
                sectype++;
            }
            tmp++;
        }
    }

    /* Free */
    free(input);

    return 0;
}

/*
 * Call CGI
 */
int
dns_selector_call_cgi(const char *remote, struct dns_query *ques, char *zone,
                      struct dns_message *msg, char *script)
{
    /* FIXME */
    char *argv[5] = {NULL, NULL, NULL, NULL, NULL};
    char *envp[4] = {NULL, NULL, NULL, NULL};
    char zoneenv[1024];
    char remoteenv[1024];
    char pathenv[1024];
    char buf[1024];
    ssize_t nr;
    int stat;
    pid_t pid;
    int fds[2];
    unsigned char *bptr;
    unsigned char *tptr;
    size_t bsize;
    size_t bmax;
    int ret;

    /* Set environment */
    (void)snprintf(zoneenv, sizeof(zoneenv), "REQUEST_ZONE=%s", zone);
    (void)snprintf(remoteenv, sizeof(remoteenv), "REMOTE_ADDR=%s", remote);
    (void)snprintf(pathenv, sizeof(pathenv), "PATH=%s", getenv("PATH"));
    envp[0] = zoneenv;
    envp[1] = remoteenv;
    envp[2] = pathenv;
    envp[3] = NULL;

    /* Pipe */
    if ( -1 == pipe(fds) ) {
        error_warn("Pipe error");
        return EX_SOFTWARE;
    }
#ifdef DEBUG
    error_msg("DEBUG: pipe fds=[%d %d]", fds[0], fds[1]);
#endif

    pid = fork();
    if ( 0 == pid ) {
        /* Close unsed read end */
        close(fds[0]);

        /* Pipe STDOUT */
        dup2(fds[1], STDOUT_FILENO);

        /* Set query */
        argv[0] = script;
        argv[1] = ques->name;
        argv[2] = (char *)dns_type2str(ques->type);
        argv[3] = (char *)dns_class2str(ques->class);

        /* Child process */
        if ( -1 == execve(argv[0], argv, envp) ) {
            /* Cannot execute CGI script */
            error_warn("Cannot execute %s.", argv[0]);
            /* Reader will see EOF */
            close(fds[1]);
            _exit(EXIT_FAILURE);
        }
        /* Not to be reached here */
        _exit(EXIT_SUCCESS);
    } else if ( pid < 0 ) {
        /* Error */
        error_warn("Fork failed");
        close(fds[0]);
        close(fds[1]);
        return EX_SOFTWARE;
    }
    /* Parent process */

    /* Close unsed write end */
    close(fds[1]);

    /* Wait the child process exit */
    waitpid(pid, &stat, WUNTRACED);

    /* Read */
    bmax = sizeof(buf);
    bsize = 0;
    bptr = malloc(bmax);
    if ( NULL == bptr ) {
        (void)close(fds[0]);
        return EX_UNAVAILABLE;
    }
    while ( (nr = read(fds[0], buf, sizeof(buf))) > 0 ) {
        if ( bsize + nr > bmax ) {
            bmax += sizeof(buf);
            tptr = realloc(bptr, bmax);
            if ( NULL == tptr ) {
                free(bptr);
                (void)close(fds[0]);
                return EX_UNAVAILABLE;
            }
            bptr = tptr;
        }
        (void)memcpy(bptr+bsize, buf, nr);
        bsize += nr;
    }

    /* Close read end */
    close(fds[0]);

    /* Check the exit status */
    if ( WIFEXITED(stat) ) {
#ifdef DEBUG
        error_msg("DEBUG: stat=%d", WEXITSTATUS(stat));
#endif
        if ( 0 != WEXITSTATUS(stat) ) {
            error_msg("CGI returned exit status %d", WEXITSTATUS(stat));
            free(bptr);
            return WEXITSTATUS(stat);
        }
    } else {
        /* Abnomally exited */
#ifdef DEBUG
        error_msg("DEBUG: pid %d, kill %d", pid, kill(pid, 0));
#endif
        free(bptr);
        return EX_SOFTWARE;
    }

    ret = _parse_cgi_output(bptr, bsize, msg);
    free(bptr);
    if ( 0 != ret ) {
        return ret;
    }

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
