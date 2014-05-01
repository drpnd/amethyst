/*_
 * Copyright 2009-2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: server.h,v c47fcc34c973 2011/02/12 06:52:22 Hirochika $ */

#ifndef _SERVER_H
#define _SERVER_H

#include "config.h"
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>

#define MAXSOCKS SOMAXCONN

#if 0
#define SERVER_FORK 1           /* Fork */
#define SERVER_PREFORK 2        /* Prefork */
#define SERVER_THREAD 3
#define SERVER_PRETHREAD 4
#define SERVER_PAIO 5           /* Pseudo asynchronous I/O */
#endif

#define SERVER_MPM_SINGLE       0
#define SERVER_MPM_FORK         1       /* Fork multi-processing module */

#if ENABLE_SSL
/* OpenSSL */
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

/*
 * SSL server
 */
struct server_ssl_parameters {
    /* Key: mandatory */
    struct {
        const char *file;
        int type;
    } key;
    /* Certificate: mandatory */
    struct {
        const char *file;
        int type;
    } cert;
};

/*
 * Server process for listening
 */
struct server {
    /* # of server sockets */
    int nsvs;
    /* Server sockets (array) */
    struct server_instance *svs;

    struct pollfd *fds;
    nfds_t nfds;                        /* # of file descriptors */

    /* Saved result for next step */
    int _rsignal;
    /* Saved errno */
    int _errno;
    /* Free call required? */
    int _need_to_free;
};

struct server_instance;
struct server_session;
struct server_session_handlers {
    /* handler */
    int (*timeout)(struct server *, struct server_instance *, void *);
    int (*start)(struct server *, struct server_instance *,
                 struct server_session *, void *);
};

struct server_instance {
    int sock;
    int pollidx;
    int socktype;
    int proto;
    int mpm;
    /* read/write */
    int (*negotiate)(const struct server_session *);
    ssize_t (*read)(const struct server_session *, void *, size_t);
    ssize_t (*write)(const struct server_session *, const void *, size_t);
    int (*shutdown)(const struct server_session *);
#if ENABLE_SSL
    SSL_CTX *sslctx;
#endif
    struct server_session_handlers handlers;
};

struct server_session {
    int sock;
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
#if ENABLE_SSL
    SSL *ssl;
#endif
};

#ifdef __cplusplus
extern "C" {
#endif

#if ENABLE_SSL
    /* Initialize SSL */
    int server_ssl_start(void);
    int server_ssl_end(void);
#endif

    /* Initialize server process */
    struct server * server_init(struct server *);

    /* Finalize server process */
    int server_release(struct server *);

    /* Open server socket */
    int server_open(struct server *, const char *, const char *, int, int,
                    int, struct server_ssl_parameters *,
                    struct server_session_handlers *);
    int
    server_tcp_open(struct server *, const char *, const char *, int,
                    struct server_session_handlers *);
#if ENABLE_SSL
    int
    server_ssl_tcp_open(struct server *, const char *, const char *, int,
                        const char *, const char *,
                        struct server_session_handlers *);
#endif
    int
    server_udp_open(struct server *, const char *, const char *, int,
                    struct server_session_handlers *);
    int
    server_open_addrinfo(struct server *, struct addrinfo *, int,
                         struct server_ssl_parameters *,
                         struct server_session_handlers *);

    /* Close server socket */
    int server_close(struct server *);

    /* Execute server process */
    int server_exec(struct server *, void *);

#if 0
    /* Accept client socket */
    int
    server_stream_accept_client(
        struct server *, struct server_cb_handlers *, int);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _SERVER_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
