/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: zone.c,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#include "config.h"
#include "dns.h"
#include "zone.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * Tokens and the queue
 */
enum _token_type{
    TOK_DIRECTIVE,              /* Not supported now */
    TOK_STRING,
    TOK_BLANK,
    TOK_NEWLINE,
    TOK_LPAREN,                 /* ( */
    TOK_RPAREN,                 /* ) */
};
struct _token {
    enum _token_type type;
    union {
        char *s;
    } c;
};
struct _token_queue_entry {
    struct _token *_e;
    struct _token_queue_entry *_next;
};
struct _token_queue {
    struct _token_queue_entry *_head;
    struct _token_queue_entry *_tail;
};

/*
 * Parser instance
 */
struct _parser {
};

/*
 * Functions for token
 */
struct _token *
_token_new(enum _token_type type)
{
    struct _token *tok;

    tok = malloc(sizeof(struct _token));
    if ( NULL == tok ) {
        return NULL;
    }
    tok->type = type;

    return tok;
}
void
_token_delete(struct _token *tok)
{
    if ( TOK_STRING == tok->type ) {
        free(tok->c.s);
    }
    free(tok);
}

/*
 * Functions for token queue
 */
static struct _token_queue *
_token_queue_new(void)
{
    struct _token_queue *tq;

    tq = malloc(sizeof(struct _token_queue));
    if ( NULL == tq ) {
        return NULL;
    }
    tq->_head = NULL;
    tq->_tail = NULL;

    return tq;
}
void
_token_queue_delete(struct _token_queue *tq)
{
    struct _token_queue_entry *e;
    struct _token_queue_entry *ne;

    e = tq->_head;
    while ( NULL != e ) {
        _token_delete(e->_e);
        ne = e->_next;
        free(e);
        e = ne;
    }

    free(tq);
}
int
_token_queue_append(struct _token_queue *tq, struct _token *tok)
{
    struct _token_queue_entry *e;

    e = malloc(sizeof(struct _token_queue_entry));
    if ( NULL == e ) {
        return -1;
    }
    e->_e = tok;
    e->_next = NULL;

    if ( NULL == tq->_tail ) {
        tq->_head = e;
        tq->_tail = e;
    } else {
        tq->_tail->_next = e;
        tq->_tail = e;
    }

    return 0;
}
struct _token *
_token_queue_pop(struct _token_queue *tq)
{
    struct _token *tok;

    if ( NULL != tq->_head ) {
        tok = tq->_head->_e;
        tq->_head = tq->_head->_next;
        if ( NULL == tq->_head ) {
            tq->_tail = NULL;
        }
    } else {
        tok = NULL;
    }

    return tok;
}

/*
 * Tokenize string
 */
static char *
_tokenize_string(FILE *fp)
{
    int c;
    char buf[4096];
    int ptr;

    /* FIXME: Support more than 4096 byte entries */
    ptr = 0;
    while ( EOF != (c = fgetc(fp))) {
        if ( isspace(c) ) {
            if ( EOF == ungetc(c, fp) ) {
                return NULL;
            }
            break;
        }
        if ( ptr > sizeof(buf) + 2 ) {
            return NULL;
        }
        buf[ptr] = c;
        ptr++;
    }
    buf[ptr] = '\0';

    return strdup(buf);
}

/*
 * Tokenize
 */
static struct _token_queue *
_tokenize(const char *filename)
{
    struct _token_queue *tq;
    struct _token *tok;
    FILE *fp;
    int c;
    int linestart;
    char *str;

    /* Open the file */
    fp = fopen(filename, "r");
    if ( NULL == fp ) {
        return NULL;
    }

    /* New token queue */
    tq = _token_queue_new();
    if ( NULL == tq ) {
        return NULL;
    }

    linestart = 1;
    while ( EOF != (c = fgetc(fp)) ) {
        /* Skip whitespace */
        if ( '\n' != c && isspace(c) ) {
            if ( linestart ) {
                /* NEWLINE */
                tok = _token_new(TOK_BLANK);
                if ( NULL == tok ) {
                    (void)fclose(fp);
                    _token_queue_delete(tq);
                    return NULL;
                }
                if ( 0 != _token_queue_append(tq, tok) ) {
                    _token_delete(tok);
                    (void)fclose(fp);
                    _token_queue_delete(tq);
                    return NULL;
                }
                linestart = 0;
            }
            continue;
        }
        linestart = 0;
        if ( '\n' == c ) {
            /* NEWLINE */
            tok = _token_new(TOK_NEWLINE);
            if ( NULL == tok ) {
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            if ( 0 != _token_queue_append(tq, tok) ) {
                _token_delete(tok);
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            linestart = 1;
        } else if ( '(' == c ) {
            /* LPAREN */
            tok = _token_new(TOK_LPAREN);
            if ( NULL == tok ) {
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            if ( 0 != _token_queue_append(tq, tok) ) {
                _token_delete(tok);
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
        } else if ( ')' == c ) {
            /* RPAREN */
            tok = _token_new(TOK_RPAREN);
            if ( NULL == tok ) {
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            if ( 0 != _token_queue_append(tq, tok) ) {
                _token_delete(tok);
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
        } else if ( ';' == c ) {
            /* Comment then skip to newline */
            while ( EOF != (c = fgetc(fp)) ) {
                if ( '\n' == c ) {
                    if ( EOF == ungetc(c, fp) ) {
                        (void)fclose(fp);
                        _token_queue_delete(tq);
                        return NULL;
                    }
                    break;
                }
            }
        } else {
            /* String ($=directive but...) */
            tok = _token_new(TOK_STRING);
            if ( NULL == tok ) {
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            if ( EOF == ungetc(c, fp) ) {
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            str = _tokenize_string(fp);
            if ( NULL == str ) {
                _token_delete(tok);
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
            tok->c.s = str;
            if ( 0 != _token_queue_append(tq, tok) ) {
                free(str);
                _token_delete(tok);
                (void)fclose(fp);
                _token_queue_delete(tq);
                return NULL;
            }
        }
    }

    (void)fclose(fp);

    return tq;
}

/*
 * Parse zone file
 */
struct dns_zone *
zone_parse_file(const char *filename, const char *zone)
{
    struct dns_zone *z;
    struct _token_queue *tq;
    struct _token *tok;
    int col;
    int soa;

    /* Initialize zone */
    z = malloc(sizeof(struct dns_zone));
    if ( NULL == z ) {
        return NULL;
    }
    z->name = strdup(zone);
    if ( NULL == z->name ) {
        free(z);
        return NULL;
    }
    z->directives.origin = NULL;
    z->directives.ttl = 86400;

    /* Tokenize */
    tq = _tokenize(filename);
    if ( NULL == tq ) {
        free(z);
        return NULL;
    }

    /* Parse */
    col = 0;
    soa = 0;
    while ( NULL != (tok = _token_queue_pop(tq)) ) {
        switch ( tok->type ) {
        case TOK_NEWLINE:
            if ( !soa ) {
                col = 0;
            }
            break;
        case TOK_BLANK:
            break;
        case TOK_LPAREN:
            if ( soa ) {
                free(z);
                _token_queue_delete(tq);
                return NULL;
            }
            soa = 1;
            break;
        case TOK_RPAREN:
            if ( !soa ) {
                free(z);
                _token_queue_delete(tq);
                return NULL;
            }
            soa = 0;
            break;
        case TOK_STRING:
            col++;
            break;
        default:
            /* Not to be reached here. */
            ;
        }
        _token_delete(tok);
    }

    /* Delete the token queue */
    _token_queue_delete(tq);

    return z;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
