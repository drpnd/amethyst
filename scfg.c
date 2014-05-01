/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: scfg.c,v 3fd7b0a2108d 2011/02/11 09:36:32 Hirochika $ */

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
static int _add_value_leaf(struct scfg_node *, char *, enum scfg_value_type);
static int _add_key_child(struct scfg_node **, char *);
static int
_parse_token_queue_block(struct scfg_token_queue *, struct scfg_node *);
static int
_parse_token_queue_line(struct scfg_token_queue *, struct scfg_node *);
static int
_parse_token_queue_list(struct scfg_token_queue *, struct scfg_node *);
static int
_parse_token_queue_root(struct scfg_token_queue *, struct scfg_node *);
static void _release_node(struct scfg_node *);

/*
 * Add value leaf to a node
 */
static int
_add_value_leaf(struct scfg_node *node, char *value, enum scfg_value_type type)
{
    struct scfg_node *tmpnode;
    char *nval;
    int errno_saved;

    if ( SCFG_NODE_ROOT != node->type && SCFG_NODE_BRANCH != node->type ){
        /* If the node is not root nor branch, the value cannot be added */
        return -1;
    }

    /* Copy the value */
    nval = strdup(value);
    if ( NULL == nval ) {
        return -1;
    }

    /* Resize branch */
    tmpnode = realloc(node->data.b.branches,
                      sizeof(struct scfg_node) * (node->data.b.n + 1));
    if ( NULL == tmpnode ) {
        errno_saved = errno;
        free(nval);
        errno = errno_saved;
        return -1;
    }
    /* Add a leaf */
    tmpnode[node->data.b.n].type = SCFG_NODE_LEAF;
    tmpnode[node->data.b.n].data.l.type = type;
    tmpnode[node->data.b.n].data.l.value = nval;
    node->data.b.branches = tmpnode;
    node->data.b.n++;

    return 0;
}

/*
 * Add a key child to a node
 */
static int
_add_key_child(struct scfg_node **node, char *key)
{
    struct scfg_node *tmpnode;
    struct scfg_node *nn;
    char *nkey;
    size_t i;
    int errno_saved;

    tmpnode = *node;

    if ( SCFG_NODE_ROOT != tmpnode->type
         && SCFG_NODE_BRANCH != tmpnode->type ) {
        /* If the node is not root nor branch, the value cannot be added */
        return -1;
    }

    /* Search a node corresponding to the specified key */
    for ( i = 0; i < tmpnode->data.b.n; i++ ) {
        if ( SCFG_NODE_BRANCH == tmpnode->data.b.branches[i].type
             && 0 == strcmp(tmpnode->data.b.branches[i].data.b.key, key) ) {
            /* Found */
            *node = &(tmpnode->data.b.branches[i]);
            /* The key already exists and skip */
            return 0;
        }
    }

    /* Copy key */
    nkey = strdup(key);
    if ( NULL == nkey ) {
        return -1;
    }

    /* Resize branch */
    nn = realloc(tmpnode->data.b.branches,
                 sizeof(struct scfg_node) * (tmpnode->data.b.n + 1));
    if ( NULL == nn ) {
        errno_saved = errno;
        free(nkey);
        errno = errno_saved;
        return -1;
    }
    /* Add a new branch with the specified key */
    nn[tmpnode->data.b.n].type = SCFG_NODE_BRANCH;
    nn[tmpnode->data.b.n].data.b.key = nkey;
    nn[tmpnode->data.b.n].data.b.branches = NULL;
    nn[tmpnode->data.b.n].data.b.n = 0;
    tmpnode->data.b.branches = nn;
    *node = &(tmpnode->data.b.branches[tmpnode->data.b.n]);
    tmpnode->data.b.n++;

    return 0;
}

/*
 * Parse a block
 */
static int
_parse_token_queue_block(struct scfg_token_queue *tq, struct scfg_node *node)
{
    struct scfg_token *tok1;
    struct scfg_token *tok2;
    int ret;

    /* Get a head token */
    tok1 = scfg_token_queue_pop(tq);
    if ( NULL == tok1 || TOK_LBRACE != tok1->type ) {
        /* Must be the beginning of block; not to be reached here */
        return -1;
    }
    scfg_token_delete(tok1);

    /* Parse tokens */
    ret = _parse_token_queue_list(tq, node);
    if  ( 0 != ret ) {
        return -1;
    }

    /* Get two tokens */
    tok1 = scfg_token_queue_pop(tq);
    tok2 = scfg_token_queue_pop(tq);
    if ( NULL != tok1 && TOK_RBRACE == tok1->type
         && NULL != tok2 && TOK_SEMICOLON == tok2->type ) {
        /* "};": End of block */
        scfg_token_delete(tok1);
        scfg_token_delete(tok2);
    } else {
        /* Parse error */
        if ( NULL != tok1 ) {
            scfg_token_delete(tok1);
        }
        if ( NULL != tok2 ) {
            scfg_token_delete(tok2);
        }
        return -1;
    }

    return 0;
}

/*
 * Parse a line (a set)
 */
static int
_parse_token_queue_line(struct scfg_token_queue *tq, struct scfg_node *node)
{
    struct scfg_node *cur;
    struct scfg_token *tok1;
    struct scfg_token *tok2;
    int ret;
    int errno_saved;

    /* Set current node */
    cur = node;
    /* While reaches end or occurs an error */
    for ( ;; ) {
        /* Get two tokens */
        tok1 = scfg_token_queue_pop(tq);
        tok2 = scfg_token_queue_head(tq);
        if ( NULL == tok1 ) {
            /* Invalid format */
            return -1;
        } else if ( NULL == tok2 ) {
            if ( TOK_SEMICOLON == tok1->type ) {
                /* Null line */
                scfg_token_delete(tok1);
                return 0;
            } else {
                /* Invalid */
                scfg_token_delete(tok1);
                return -1;
            }
        } else {
            /* tok1 tok2 */
            if ( TOK_SEMICOLON == tok2->type ) {
                /* Value ("tok1;") */
                tok2 = scfg_token_queue_pop(tq);
                if ( TOK_KEYWORD == tok1->type ) {
                    /* Value (Keyword) */
                    ret = _add_value_leaf(cur, tok1->c.s, SCFG_VALUE_KW);
                    errno_saved = errno;
                    scfg_token_delete(tok1);
                    scfg_token_delete(tok2);
                    if ( 0 != ret ) {
                        errno = errno_saved;
                        return -1;
                    }
                    return 0;
                } else if ( TOK_STRING == tok1->type ) {
                    /* Value (String) */
                    ret = _add_value_leaf(cur, tok1->c.s, SCFG_VALUE_STRING);
                    errno_saved = errno;
                    scfg_token_delete(tok1);
                    scfg_token_delete(tok2);
                    if ( 0 != ret ) {
                        errno = errno_saved;
                        return -1;
                    }
                    return 0;
                } else {
                    /* Invalid format */
                    scfg_token_delete(tok1);
                    scfg_token_delete(tok2);
                    return -1;
                }
            } else if ( TOK_LBRACE == tok2->type ) {
                /* New block */
                /* First add key */
                if ( TOK_KEYWORD == tok1->type ) {
                    ret = _add_key_child(&cur, tok1->c.s);
                    errno_saved = errno;
                    scfg_token_delete(tok1);
                    if ( 0 != ret ) {
                        errno = errno_saved;
                        return -1;
                    }
                } else {
                    /* Parse error */
                    scfg_token_delete(tok1);
                    return -1;
                }
                /* Parse the block */
                ret = _parse_token_queue_block(tq, cur);
                if ( 0 != ret ) {
                    return -1;
                }
                return 0;
                /* Continue */
            } else {
                /* Key */
                if ( TOK_KEYWORD == tok1->type ) {
                    ret = _add_key_child(&cur, tok1->c.s);
                    scfg_token_delete(tok1);
                    if ( 0 != ret ) {
                        return -1;
                    }
                    /* Continue */
                } else if ( TOK_STRING == tok1->type ) {
                    ret = _add_key_child(&cur, tok1->c.s);
                    scfg_token_delete(tok1);
                    if ( 0 != ret ) {
                        return -1;
                    }
                    /* Continue */
                } else {
                    /* Invalid format */
                    scfg_token_delete(tok1);
                    return -1;
                }
            }
        }
    }

    return 0;
}

/*
 * Parse list (inside in a block)
 */
static int
_parse_token_queue_list(struct scfg_token_queue *tq, struct scfg_node *node)
{
    struct scfg_token *cur;
    int ret;

    while ( NULL != scfg_token_queue_head(tq) ) {
        cur = scfg_token_queue_head(tq);
        if ( TOK_RBRACE == cur->type ) {
            /* End of list */
            break;
        }
        /* Parse one line */
        ret = _parse_token_queue_line(tq, node);
        if ( 0 != ret ) {
            return -1;
        }
    }

    return 0;
}

/*
 * Parse token queue
 */
static int
_parse_token_queue_root(struct scfg_token_queue *tq, struct scfg_node *node)
{
    struct scfg_token *tok;
    int ret;

    /* Get tokens */
    tok = scfg_token_queue_head(tq);
    if ( NULL == tok ) {
        /* End of token */
        return 0;
    }
    ret = _parse_token_queue_list(tq, node);
    if ( 0 != ret ) {
        return -1;
    }
    if ( NULL != scfg_token_queue_head(tq) ) {
        /* Tokenize error */
        return -1;
    }

    return 0;
}

/*
 * Parse configuration file
 */
scfg_t *
scfg_parse(const char *filename)
{
    scfg_t *cfg;
    struct scfg_token_queue *tq;
    int ret;

    /* Tokenize */
    tq = scfg_tokenize(filename);
    if ( NULL == tq ) {
        /* Error */
        return NULL;
    }

    /* Allocate config tree */
    cfg = malloc(sizeof(scfg_t));
    if ( NULL == cfg ) {
        /* Memory error */
        scfg_token_queue_delete(tq);
        return NULL;
    }
    cfg->root.type = SCFG_NODE_ROOT;;
    cfg->root.data.b.n = 0;
    cfg->root.data.b.branches = NULL;

    /* Parse */
    ret = _parse_token_queue_root(tq, &(cfg->root));
    if ( 0 != ret ) {
        scfg_release(cfg);
        scfg_token_queue_delete(tq);
        return NULL;
    }
    scfg_token_queue_delete(tq);

    return cfg;
}

/*
 * Release configuration
 */
static void
_release_node(struct scfg_node *node)
{
    int i;

    if ( SCFG_NODE_LEAF == node->type ) {
        free(node->data.l.value);
    } else {
        for ( i = 0; i < node->data.b.n; i++ ) {
            _release_node(&(node->data.b.branches[i]));
        }
        free(node->data.b.key);
        free(node->data.b.branches);
    }
}

/*
 * Release configuration
 */
void
scfg_release(scfg_t *cfg)
{
    int i;

    /* Release all nodes */
    for ( i = 0; i < cfg->root.data.b.n; i++ ) {
        _release_node(&(cfg->root.data.b.branches[i]));
    }

    free(cfg);
}

/*
 * Search nodes
 */
static struct scfg_node *
_search_node(struct scfg_node *node, const char *key)
{
    int i;
    size_t len;
    struct scfg_node *ret;

    if ( SCFG_NODE_LEAF == node->type ) {
        return NULL;
    } else if ( SCFG_NODE_ROOT == node->type ) {
        for ( i = 0; i < node->data.b.n; i++ ) {
            ret = _search_node(&(node->data.b.branches[i]), key);
            if ( NULL != ret ) {
                return ret;
            }
        }
    } else {
        for ( i = 0; i < node->data.b.n; i++ ) {
            if ( 0 == strcmp(key, node->data.b.key) ) {
                len = strlen(key);
                if ( '\0' == key[len+1] ) {
                    /* End of search */
                    return node;
                } else {
                    /* Proceed */
                    ret = _search_node(&(node->data.b.branches[i]), key+len+1);
                    if ( NULL != ret ) {
                        return ret;
                    }
                }
            }
        }
    }

    /* Not found */
    return NULL;
}

/*
 * Get value
 */
char *
scfg_get_values(scfg_t *cfg, const char *ptr)
{
    struct scfg_node *node;
    int i;
    int cnt;
    size_t len;
    char *ret;
    char *str;

    ret = NULL;
    /* Reset error */
    errno = 0;

    node = _search_node(&cfg->root, ptr);
    if ( NULL != node ) {
        if ( SCFG_NODE_BRANCH == node->type ) {
            /* Check the size */
            len = 0;
            cnt = 0;
            for ( i = 0; i < node->data.b.n; i++ ) {
                if ( SCFG_NODE_LEAF == node->data.b.branches[i].type ) {
                    cnt++;
                    len += strlen(node->data.b.branches[i].data.l.value);
                }
            }
            /* Allocate memory */
            ret = malloc(sizeof(char) * (len + cnt + 1));
            if ( NULL == ret ) {
                /* Memory error */
                return NULL;
            }
            /* Copy */
            str = ret;
            for ( i = 0; i < node->data.b.n; i++ ) {
                if ( SCFG_NODE_LEAF == node->data.b.branches[i].type ) {
                    (void)strcpy(str, node->data.b.branches[i].data.l.value);
                    str += strlen(str) + 1;
                }
            }
            *str = '\0';
        }
    }

    return ret;
}

/*
 * Get keys
 */
char *
scfg_get_keys(scfg_t *cfg, const char *ptr)
{
    struct scfg_node *node;
    int i;
    int cnt;
    size_t len;
    char *ret;
    char *str;

    ret = NULL;
    node = _search_node(&cfg->root, ptr);
    if ( NULL != node ) {
        if ( SCFG_NODE_BRANCH == node->type ) {
            /* Check the size */
            len = 0;
            cnt = 0;
            for ( i = 0; i < node->data.b.n; i++ ) {
                if ( SCFG_NODE_BRANCH == node->data.b.branches[i].type ) {
                    cnt++;
                    len += strlen(node->data.b.branches[i].data.b.key);
                }
            }
            /* Allocate memory */
            ret = malloc(sizeof(char) * (len + cnt + 1));
            if ( NULL == ret ) {
                /* Memory error */
                return NULL;
            }
            /* Copy */
            str = ret;
            for ( i = 0; i < node->data.b.n; i++ ) {
                if ( SCFG_NODE_BRANCH == node->data.b.branches[i].type ) {
                    (void)strcpy(str, node->data.b.branches[i].data.b.key);
                    str += strlen(str) + 1;
                }
            }
            *str = '\0';
        }
    }

    return ret;
}

/*
 * Print configuration (for debugging)
 */
static int
_print_node(struct scfg_node *node, int level)
{
    int i;

    if ( SCFG_NODE_LEAF == node->type ) {
        for ( i = 0; i < level; i++ ) {
            printf(" ");
        }
        printf("%s\n", node->data.l.value);
    } else {
        for ( i = 0; i < level; i++ ) {
            printf(" ");
        }
        printf("%s\n", node->data.b.key);

        for ( i = 0; i < node->data.b.n; i++ ) {
            _print_node(&(node->data.b.branches[i]), level+1);
        }
    }

    return 0;
}
int
scfg_print(scfg_t *cfg)
{
    int i;

    for ( i = 0; i < cfg->root.data.b.n; i++ ) {
        _print_node(&(cfg->root.data.b.branches[i]), 0);
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
