/*_
 * Copyright 2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#ifndef _SSLSERVER_H
#define _SSLSERVER_H

#include <poll.h>
#include <netdb.h>
/* OpenSSL */
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MAXSSLSOCKS SOMAXCONN

#define SSLSERVER_MPM_SINGLE       0
#define SSLSERVER_MPM_FORK         1       /* Fork multi-processing module */

/*
 * Server process for listening
 */
struct sslserver {
    /* # of server sockets */
    int nsvs;
    /* Server sockets (array) */
    struct sslserver_instance *svs;

    struct pollfd *fds;
    nfds_t nfds;                        /* # of file descriptors */

    /* Saved result for next step */
    int _rsignal;
    /* Saved errno */
    int _errno;
    /* Free call required? */
    int _need_to_free;
};

struct sslserver_instance;
struct sslserver_session;
struct sslserver_session_handlers {
    /* handler */
    int (*timeout)(struct sslserver *, struct sslserver_instance *, void *);
    int (*start)(struct sslserver *, struct sslserver_instance *,
                 struct sslserver_session *, void *);
};

struct sslserver_instance {
    int sock;
    int pollidx;
    int socktype;
    int proto;
    int mpm;
    SSL_CTX *ctx;
    struct sslserver_session_handlers handlers;
};

struct sslserver_session {
    int sock;
    SSL *ssl;
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
};

#ifdef __cplusplus
extern "C" {
#endif

    /* Initialize server process */
    struct sslserver * sslserver_init(struct sslserver *);

    /* Finalize server process */
    int sslserver_release(struct sslserver *);

    /* Open server socket */
    int
    sslserver_open(struct sslserver *, const char *, const char *, int, int,
                   int, const char *, const char *,
                   struct sslserver_session_handlers *);
    int
    sslserver_tcp_open(struct sslserver *, const char *, const char *, int,
                       const char *, const char *,
                       struct sslserver_session_handlers *);
    int
    sslserver_udp_open(struct sslserver *, const char *, const char *, int,
                       const char *, const char *,
                       struct sslserver_session_handlers *);
    int
    sslserver_open_addrinfo(struct sslserver *, struct addrinfo *, int,
                            const char *, const char *,
                            struct sslserver_session_handlers *);

    /* Close server socket */
    int sslserver_close(struct sslserver *);

    /* Execute server process */
    int sslserver_exec(struct sslserver *, void *);

#ifdef __cplusplus
}
#endif

#endif /* _SSLSERVER_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
