/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: scfg_private.h,v 891c87227127 2011/01/28 12:25:31 Hirochika $ */

#ifndef _SCFG_PRIVATE_H
#define _SCFG_PRIVATE_H

#include "scfg.h"

/*
 * Tokens and the queue
 */
enum scfg_token_type {
    TOK_KEYWORD,
    TOK_STRING,
    TOK_SEMICOLON,
    TOK_LPAREN,                 /* ( */
    TOK_RPAREN,                 /* ) */
    TOK_LBRACE,                 /* { */
    TOK_RBRACE,                 /* } */
};
struct scfg_token {
    enum scfg_token_type type;
    union {
        char *s;                /* For TOK_KEYWORD or TOK_STRING */
    } c;
};
struct _token_queue_entry {
    struct scfg_token *_e;
    struct _token_queue_entry *_next;
};
struct scfg_token_queue {
    struct _token_queue_entry *_head;
    struct _token_queue_entry *_tail;
};

/*
 * Node type
 */
enum scfg_node_type {
    SCFG_NODE_ROOT,
    SCFG_NODE_BRANCH,
    SCFG_NODE_LEAF,
};
enum scfg_value_type {
    SCFG_VALUE_KW,
    SCFG_VALUE_STRING,
};

/*
 * Configuration leaf
 */
struct scfg_leaf {
    enum scfg_value_type type;
    char *value;
};

/*
 * Configuration node
 */
struct scfg_node {
    enum scfg_node_type type;
    union {
        struct {
            char *key;
            /* List */
            struct scfg_node *branches;
            size_t n;
        } b;
        struct scfg_leaf l;
    } data;
};

/*
 * Configuration tree
 */
struct _scfg {
    /* List */
    struct scfg_node root;
};

#ifdef __cplusplus
extern "C" {
#endif

    struct scfg_token_queue * scfg_tokenize(const char *);

    /* Token */
    struct scfg_token * scfg_token_new(enum scfg_token_type);
    void scfg_token_delete(struct scfg_token *);

    /* Token queue */
    struct scfg_token_queue * scfg_token_queue_new(void);
    void scfg_token_queue_delete(struct scfg_token_queue *);
    struct scfg_token * scfg_token_queue_pop(struct scfg_token_queue *);
    struct scfg_token * scfg_token_queue_head(struct scfg_token_queue *);

#ifdef __cplusplus
}
#endif

#endif /* _SCFG_PRIVATE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
