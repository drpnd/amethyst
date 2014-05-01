/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: rbtree.h,v 572f48d68068 2010/11/09 03:49:40 Hirochika $ */

#ifndef _RBTREE_H
#define _RBTREE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

enum rbtree_color {
    RBTREE_BLACK,
    RBTREE_RED,
};

struct rbtree_node {
    void *key;
    struct rbtree_node *parent;
    struct rbtree_node *left;
    struct rbtree_node *right;
    enum rbtree_color color;
};
struct rbtree {
    struct rbtree_node *root;
    int (*compare)(const void *, const void *);
    /* Need to free on release? */
    int _need_to_free:1;
};
struct rbtree_iterator {
    struct rbtree_node *cur;
    struct rbtree_node *prev;
    /* Need to free on release? */
    int _need_to_free:1;
};

#ifdef __cplusplus
extern "C" {
#endif

    struct rbtree *
    rbtree_init(struct rbtree *, int (*)(const void *, const void *));
    void rbtree_release(struct rbtree *);
    void
    rbtree_release_callback(struct rbtree *, void (*)(void *, void *), void *);
    void * rbtree_search(struct rbtree *, void *);
    int rbtree_insert(struct rbtree *, void *);
    void * rbtree_delete(struct rbtree *, void *);
    void * rbtree_pop(struct rbtree *);
    void * rbtree_min(struct rbtree *);
    void rbtree_exec_all(struct rbtree *, void (*)(void *, void *), void *);

    struct rbtree_iterator *
    rbtree_iterator_init(struct rbtree_iterator *);
    void
    rbtree_iterator_release(struct rbtree_iterator *);
    void * rbtree_iterator_cur(struct rbtree_iterator *);
    void * rbtree_iterator_next(struct rbtree *, struct rbtree_iterator *);
    void rbtree_iterator_rewind(struct rbtree_iterator *);

#ifdef __cplusplus
}
#endif

#endif /* _RBTREE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
