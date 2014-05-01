/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: tokenizer.c,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#include "config.h"

#include "scfg.h"
#include "scfg_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/*
 * Prototype declarations
 */
static __inline__ int
_token_queue_append(struct scfg_token_queue *, struct scfg_token *);
static __inline__ int
_token_queue_append_single(struct scfg_token_queue *, enum scfg_token_type);
static __inline__ int
_token_queue_append_ks(struct scfg_token_queue *, enum scfg_token_type, char *);
static __inline__ void _skip_whitespaces(char **);
static __inline__ void _skip_linecomment(char **);
static __inline__ void _skip_blockcomment(char **);
static __inline__ int _isckeyword(int);
static int _tokenize_keword(struct scfg_token_queue *, char **);
static int _tokenize_string(struct scfg_token_queue *, char **);
static struct scfg_token_queue * _tokenize(char *);

/*
 * Allocate new token
 */
struct scfg_token *
scfg_token_new(enum scfg_token_type type)
{
    struct scfg_token *tok;

    tok = malloc(sizeof(struct scfg_token));
    if ( NULL == tok ) {
        return NULL;
    }
    tok->type = type;

    return tok;
}

/*
 * Deallocate token delete
 */
void
scfg_token_delete(struct scfg_token *tok)
{
    if ( TOK_KEYWORD == tok->type || TOK_STRING == tok->type ) {
        /* Free string */
        free(tok->c.s);
    }
    /* Free token */
    free(tok);
}

/*
 * Allocate new token queue
 */
struct scfg_token_queue *
scfg_token_queue_new(void)
{
    struct scfg_token_queue *tq;

    tq = malloc(sizeof(struct scfg_token_queue));
    if ( NULL == tq ) {
        return NULL;
    }
    tq->_head = NULL;
    tq->_tail = NULL;

    return tq;
}

/*
 * Delete token queue
 */
void
scfg_token_queue_delete(struct scfg_token_queue *tq)
{
    struct _token_queue_entry *e;
    struct _token_queue_entry *ne;

    /* Deallocate all tokens in the queue */
    e = tq->_head;
    while ( NULL != e ) {
        scfg_token_delete(e->_e);
        ne = e->_next;
        free(e);
        e = ne;
    }

    free(tq);
}

/*
 * Append a token to a queue
 */
static __inline__ int
_token_queue_append(struct scfg_token_queue *tq, struct scfg_token *tok)
{
    struct _token_queue_entry *e;

    /* Allocate new entry */
    e = malloc(sizeof(struct _token_queue_entry));
    if ( NULL == e ) {
        return -1;
    }
    e->_e = tok;
    e->_next = NULL;

    /* Append to the tail of the queue */
    if ( NULL == tq->_tail ) {
        tq->_head = e;
        tq->_tail = e;
    } else {
        tq->_tail->_next = e;
        tq->_tail = e;
    }

    return 0;
}

/*
 * Append a single character token
 */
static __inline__ int
_token_queue_append_single(struct scfg_token_queue *tq,
                           enum scfg_token_type type)
{
    struct scfg_token *tok;

    /* Allocate new token */
    tok = scfg_token_new(type);
    if ( NULL == tok ) {
        return -1;
    }

    /* Append the allocated token to the tail of the queue */
    if ( 0 != _token_queue_append(tq, tok) ) {
        scfg_token_delete(tok);
        return -1;
    }

    return 0;
}

/*
 * Append a keyword or string token
 */
static __inline__ int
_token_queue_append_ks(struct scfg_token_queue *tq, enum scfg_token_type type,
                       char *k)
{
    struct scfg_token *tok;

    /* Allocate new token */
    tok = scfg_token_new(type);
    if ( NULL == tok ) {
        return -1;
    }
    tok->c.s = strdup(k);
    if ( NULL == tok->c.s ) {
        scfg_token_delete(tok);
        return -1;
    }

    /* Append the token to the queue */
    if ( 0 != _token_queue_append(tq, tok) ) {
        scfg_token_delete(tok);
        return -1;
    }

    return 0;
}


/*
 * Pop a token from a queue
 */
struct scfg_token *
scfg_token_queue_pop(struct scfg_token_queue *tq)
{
    struct scfg_token *tok;

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
 * Return a token at the head of a queue
 */
struct scfg_token *
scfg_token_queue_head(struct scfg_token_queue *tq)
{
    struct scfg_token *tok;

    if ( NULL != tq->_head ) {
        tok = tq->_head->_e;
    } else {
        tok = NULL;
    }

    return tok;
}

/*
 * Print all tokens in a token queue
 */
int
scfg_token_queue_print(struct scfg_token_queue *tq)
{
    struct scfg_token *tok;

    while ( NULL != (tok = scfg_token_queue_pop(tq)) ) {
        switch ( tok->type ) {
        case TOK_STRING:
        case TOK_KEYWORD:
            (void)printf(" %s ", tok->c.s);
            break;
        case TOK_SEMICOLON:
            (void)printf(";\n");
            break;
        case TOK_LPAREN:
            (void)printf("(");
            break;
        case TOK_RPAREN:
            (void)printf(")");
            break;
        case TOK_LBRACE:
            (void)printf("{\n");
            break;
        case TOK_RBRACE:
            (void)printf("}");
            break;
        default:
            /* Nothing to do */
            ;
        }
        /* Deallocate the token */
        scfg_token_delete(tok);
    }

    return 0;
}

/*
 * Skip white space
 */
static __inline__ void
_skip_whitespaces(char **s)
{
    /* Skip until ending space or string */
    while ( isspace(**s) && '\0' != **s ) {
        (*s)++;
    }
}

/*
 * Skip line comment
 */
static __inline__ void
_skip_linecomment(char **s)
{
    /* Skip until ending space or string */
    while ( '\n' != **s && '\0' != **s ) {
        (*s)++;
    }
}

/*
 * Skip block comment
 */
static __inline__ void
_skip_blockcomment(char **s)
{
    /* Skip until ending space or string */
    while ( '\0' != **s ) {
        if ( '*' == **s && '/' == *((*s) + 1) ) {
            (*s) += 2;
            break;
        } else {
            (*s)++;
        }
    }
}

/*
 * Check whether the character is allowed as first character of keyword
 */
static __inline__ int
_isckeyword(int c)
{
    if ( isalnum(c) || '_' == c || '-' == c || '.' == c || '*' == c \
         || ':' == c ) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * Tokenize keyword
 */
static int
_tokenize_keword(struct scfg_token_queue *tq, char **s)
{
    char *s0;
    char *s1;
    char *sr;
    int len;
    int ret;

    s0 = *s;
    while ( _isckeyword(**s) ) {
        (*s)++;
    }
    s1 = *s;

    /* Allocate */
    len = s1 - s0;

    sr = malloc(sizeof(char) * (len + 1));
    if ( NULL == sr ) {
        return -1;
    }
    (void)memcpy(sr, s0, len);
    sr[len] = '\0';

    ret = _token_queue_append_ks(tq, TOK_KEYWORD, sr);
    free(sr);
    if ( 0 != ret ) {
        return -1;
    }

    return 0;
}

/*
 * Tokenize string
 */
static int
_tokenize_string(struct scfg_token_queue *tq, char **s)
{
    char term;
    char *s0;
    char *s1;
    char *sr;
    int len;
    int ret;
    int i;
    int ptr;

    term = **s;
    (*s)++;

    s0 = *s;
    while ( term != **s && '\0' != **s ) {
        if ( '\\' == **s ) {
            /* Escaped */
            (*s)++;
            if ( '\0' == **s ) {
                /* Invalid */
                return -1;
            }
        }
        (*s)++;
    }
    s1 = *s;
    if ( term == **s ) {
        (*s)++;
    } else {
        /* Invalid */
        return -1;
    }

    /* Allocate */
    len = s1 - s0;

    /* Memory allocation */
    sr = malloc(sizeof(char) * (len + 1));
    if ( NULL == sr ) {
        return -1;
    }
    (void)memcpy(sr, s0, len);
    sr[len] = '\0';

    /* Normalize; N.B., the allocated memory size may be larger than required */
    ptr = 0;
    for ( i = 0; i < len; i++ ) {
        if ( '\\' != sr[i] ) {
            sr[ptr] = sr[i];
            ptr++;
        }
    }

    ret = _token_queue_append_ks(tq, TOK_KEYWORD, sr);
    free(sr);
    if ( 0 != ret ) {
        return -1;
    }

    return 0;
}

/*
 * tokenize the input string
 */
static struct scfg_token_queue *
_tokenize(char *s)
{
    struct scfg_token_queue *tq;
    int ret;

    /* New token queue */
    tq = scfg_token_queue_new();
    if ( NULL == tq ) {
        return NULL;
    }

    while ( '\0' != *s ) {
        /* Skip white space */
        _skip_whitespaces(&s);

        if ( '\0' == *s ) {
            break;
        }

        switch ( *s ) {
        case '{':
            /* LBRACE */
            ret = _token_queue_append_single(tq, TOK_LBRACE);
            if ( 0 != ret ) {
                /* Error */
                scfg_token_queue_delete(tq);
                return NULL;
            }
            s++;
            break;
        case '}':
            /* RBRACE */
            ret = _token_queue_append_single(tq, TOK_RBRACE);
            if ( 0 != ret ) {
                /* Error */
                scfg_token_queue_delete(tq);
                return NULL;
            }
            s++;
            break;
        case '(':
            /* LPAREN */
            ret = _token_queue_append_single(tq, TOK_LPAREN);
            if ( 0 != ret ) {
                /* Error */
                scfg_token_queue_delete(tq);
                return NULL;
            }
            s++;
            break;
        case ')':
            /* RPAREN */
            ret = _token_queue_append_single(tq, TOK_RPAREN);
            if ( 0 != ret ) {
                /* Error */
                scfg_token_queue_delete(tq);
                return NULL;
            }
            s++;
            break;
        case ';':
            /* SEMICOLON */
            ret = _token_queue_append_single(tq, TOK_SEMICOLON);
            if ( 0 != ret ) {
                /* Error */
                scfg_token_queue_delete(tq);
                return NULL;
            }
            s++;
            break;
        case '#':
            /* Comment */
            _skip_linecomment(&s);
            break;
        default:
            /* Comment, keyword or string */
            if ( '/' == *s && '/' == *(s+1) ) {
                _skip_linecomment(&s);
            } else if ( '/' == *s && '*' == *(s+1) ) {
                _skip_blockcomment(&s);
            } else if ( _isckeyword(*s) ) {
                ret = _tokenize_keword(tq, &s);
                if ( 0 != ret ) {
                    /* Error */
                    scfg_token_queue_delete(tq);
                    return NULL;
                }
            } else if ( '"' == *s || '\'' == *s ) {
                ret = _tokenize_string(tq, &s);
                if ( 0 != ret ) {
                    /* Error */
                    scfg_token_queue_delete(tq);
                    return NULL;
                }
            } else {
                /* Tokenize error */
                scfg_token_queue_delete(tq);
                return NULL;
            }
            break;
        }
    }

    return tq;
}

/*
 * Tokenize
 */
struct scfg_token_queue *
scfg_tokenize(const char *filename)
{
    struct scfg_token_queue *tq;
    FILE *fp;
    char *s;
    off_t n;
    int errno_saved;

    /* Open the file */
    fp = fopen(filename, "r");
    if ( NULL == fp ) {
        /* Cannot open the file */
        return NULL;
    }
    /* Get file size */
    (void)fseeko(fp, 0L, SEEK_END);
    n = ftello(fp);
    (void)fseeko(fp, 0L, SEEK_SET);

    /* Allocate */
    s = malloc(sizeof(char) * (n + 1));
    if ( NULL == s ) {
        errno_saved = errno;
        fclose(fp);
        errno = errno_saved;
        return NULL;
    }
    fread(s, sizeof(char), n, fp);
    s[n] = '\0';

    /* Close the file */
    (void)fclose(fp);

    tq = _tokenize(s);
    errno_saved = errno;
    free(s);
    if ( NULL == tq ) {
        errno = errno_saved;
        return NULL;
    }

    return tq;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
