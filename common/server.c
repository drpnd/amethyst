/*_
 * Copyright 2009-2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: server.c,v c47fcc34c973 2011/02/12 06:52:22 Hirochika $ */

#include "error.h"
#include "server.h"
#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
/* Socket */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>         /* in_addr */
#include <unistd.h>             /* close */
#include <netdb.h>
#include <sys/wait.h>

#if ENABLE_SSL
/* OpenSSL */
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#if 0
/*
 * Prototype declarations
 */
static int
_accept_stream(struct server *, struct server_cb_handlers *, int);
static __inline__ int
_recv_dgram(struct server *, struct server_cb_handlers *, int, void *);
static __inline__ struct server_stream_client * _stream_client_new(int);
static __inline__ void _stream_client_delete(struct server_stream_client *);
static void _sigterm_handler(int);

#endif

static ssize_t _read(const struct server_session *, void *, size_t);
static ssize_t _write(const struct server_session *, const void *, size_t);
static int _negotiate(const struct server_session *);
static int _shutdown(const struct server_session *);
#if ENABLE_SSL
static ssize_t _ssl_read(const struct server_session *, void *, size_t);
static ssize_t _ssl_write(const struct server_session *, const void *, size_t);
static int _ssl_negotiate(const struct server_session *);
static int _ssl_shutdown(const struct server_session *);
#endif

/* Signal result */
static int rsignal = 0;

static void
_sigterm_handler(int signo)
{
    rsignal = 1;
}

static ssize_t
_read(const struct server_session *sess, void *buf, size_t num)
{
    return read(sess->sock, buf, num);
}
static ssize_t
_write(const struct server_session *sess, const void *buf, size_t num)
{
    return write(sess->sock, buf, num);
}
static int
_negotiate(const struct server_session *sess)
{
    return 0;
}
static int
_shutdown(const struct server_session *sess)
{
    return shutdown(sess->sock, SHUT_RDWR);
}
#if ENABLE_SSL
static ssize_t
_ssl_read(const struct server_session *sess, void *buf, size_t num)
{
    return SSL_read(sess->ssl, buf, num);
}
static ssize_t
_ssl_write(const struct server_session *sess, const void *buf, size_t num)
{
    return SSL_write(sess->ssl, buf, num);
}
static int
_ssl_negotiate(const struct server_session *sess)
{
    char errbuf[128];
    if ( SSL_accept(sess->ssl) <= 0 ) {
        /* Failed the SSL handshake */
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        error_warn("%s", errbuf);
        return -1;
    }
    return 0;
}
static int
_ssl_shutdown(const struct server_session *sess)
{
    SSL_shutdown(sess->ssl);
    (void)shutdown(sess->sock, SHUT_RDWR);
    return 0;
}
#endif

#if ENABLE_SSL
/*
 * Start SSL
 *      This function loads OpenSSL libraries and error strings
 *
 * RETURN VALUES
 *      On successful completion server_ssl_start() returns 0.
 */
int
server_ssl_start(void)
{
    uint16_t seed;

    /* Initialize SSL */
    /*srand((unsigned)time(NULL));*/
    SSL_load_error_strings();
    SSL_library_init();
    RAND_poll();
    while ( 0 == RAND_status () ) {
        /* cf: http://www.openssl.org/docs/crypto/RAND_add.html */
        seed = rand() % 65536;
        RAND_seed(&seed, sizeof(seed));
    }

    return 0;
}

/*
 * End SSL
 *      This function mekes error strings free.
 *
 * RETURN VALUES
 *      This function always returns 0.
 */
int
server_ssl_end(void)
{
    /* Free error strings */
    ERR_free_strings();

    return 0;
}
#endif

/*
 * Initialize server.
 *
 * RETURN VALUES
 *      On successful completion server_init() returns 0.  Otherwise, NULL is
 *      returned.
 */
struct server *
server_init(struct server *srv)
{
    /* Need to allocate? */
    if ( NULL == srv ) {
        srv = malloc(sizeof(struct server));
        if ( NULL == srv ) {
            /* Memory error */
            assert( ENOMEM == errno );
            return NULL;
        }
        srv->_need_to_free = 1;
    } else {
        srv->_need_to_free = 0;
    }
    /* NULL reset */
    srv->svs = NULL;

    /* Prepare for server sockets. */
    srv->nsvs = 0;

    /* Received signal */
    srv->_rsignal = 0;

    /* Prepare for both server and client sockets. */
    srv->nfds = MAXSOCKS;
    srv->fds = malloc(sizeof(struct pollfd) * srv->nfds);

    if ( NULL == srv->fds ) {
        /* Memory error */
        assert( ENOMEM == errno );
        /* Free server process instance. */
        if ( srv->_need_to_free ) {
            free(srv);
        }

        return NULL;
    }

    return srv;
}

/*
 * Release server.
 *
 * RETURN VALUES
 *      A non-zero is returned if an error occurs, otherwise the return value is
 *      0.
 */
int
server_release(struct server *srv)
{
    /* Free all sockets */
    free(srv->fds);
    /* Need to free memory? */
    if ( srv->_need_to_free ) {
        free(srv);
    }

    return 0;
}

/*
 * Open server socket.
 *
 * RETURN VALUES
 *      The function server_open() returns the number of sockets opened in this
 *      function.  If an error occurs, the return value is -1.
 */
int
server_open(struct server *srv, const char *host, const char *port,
            int socktype, int proto, int mpm,
            struct server_ssl_parameters *sslparams,
            struct server_session_handlers *handlers)
{
    struct addrinfo hints;
    struct addrinfo *resai;
    struct addrinfo *ai;
    int ret;

    /* Prepare for opening server socket. */
    (void)memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_protocol = proto;

    /* Get port information from asciz. */
    ret = getaddrinfo(host, port, &hints, &resai);
    if ( 0 != ret ) {
        /* An error occurs. */
        error_msg(errstr.server, gai_strerror(ret));
        return -1;
    }

    /* Reset fd_set. */
    for ( ai = resai; NULL != ai; ai = ai->ai_next ) {
        if ( -1 == server_open_addrinfo(srv, ai, mpm, sslparams, handlers) ) {
            /* Socket or memory error, ignore. */
            continue;
        }
    }
    /* Free the result of getaddrinfo. */
    freeaddrinfo(resai);

    return srv->nsvs;
}

/*
 * Open TCP server socket.
 *
 * RETURN VALUES
 *      The function server_open() returns the number of sockets opened in this
 *      function.  If an error occurs, the return value is -1.
 */
int
server_tcp_open(struct server *srv, const char *host, const char *port, int mpm,
                struct server_session_handlers *handlers)
{
    return server_open(srv, host, port, SOCK_STREAM, IPPROTO_TCP, mpm, NULL,
                       handlers);
}

#if ENABLE_SSL
/*
 * Open SSL/TCP server socket.
 *
 * RETURN VALUES
 *      The function server_open() returns the number of sockets opened in this
 *      function.  If an error occurs, the return value is -1.
 */
int
server_ssl_tcp_open(struct server *srv, const char *host, const char *port,
                    int mpm, const char *key, const char *cert,
                    struct server_session_handlers *handlers)
{
    struct server_ssl_parameters sslparams;

    sslparams.key.file = key;
    sslparams.key.type = SSL_FILETYPE_PEM;
    sslparams.cert.file = cert;
    sslparams.cert.type = SSL_FILETYPE_PEM;

    return server_open(srv, host, port, SOCK_STREAM, IPPROTO_TCP, mpm,
                       &sslparams, handlers);
}
#endif

/*
 * Open UDP server socket.
 *
 * RETURN VALUES
 *      The function server_open() returns the number of sockets opened in this
 *      function.  If an error occurs, the return value is -1.
 */
int
server_udp_open(struct server *srv, const char *host, const char *port, int mpm,
                struct server_session_handlers *handlers)
{
    return server_open(srv, host, port, SOCK_DGRAM, IPPROTO_UDP, mpm, NULL,
                       handlers);
}

/*
 * Open server's addrinfo.
 *
 * RETURN VALUES
 *      The function server_open_addrinfo() returns -1 if an error occurs.
 *      On successful completion, the return value is 0.
 */
int
server_open_addrinfo(struct server *srv, struct addrinfo *ai, int mpm,
                     struct server_ssl_parameters *sslparams,
                     struct server_session_handlers *handlers)
{
    int s;
    int ret;
    int optval;
    struct server_instance *srvs;
#if ENABLE_SSL
    /* For SSL */
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    char errbuf[128];
#endif

    /* Check the number of opened sockets. */
    if ( srv->nsvs >= MAXSOCKS ) {
        /* If the number of sockets become the maximum size, then terminate
           this loop. */
        error_sys_msg(errstr.server, "Too many sockets.");
        return -1;
    }

    /* Check enable option for address families. */
    if ( AF_INET == ai->ai_family ) {
#if !ENABLE_IP4
        return 0;
#endif
    } else if ( AF_INET6 == ai->ai_family ) {
#if !ENABLE_IP6
        return 0;
#endif
    } else {
        return 0;
    }

    /* Open a socket. */
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if ( s < 0 ) {
        /* Error on opening the socket. */
        error_sys_msg(errstr.server, "Opening socket");
        return -1;
    }
    /* Set option to re-use socket which has IME-WAIT status. */
    optval = 1;
    ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if ( -1 == ret ) {
        /* Error on setting the option. */
        error_sys_msg(errstr.server, "Setting secket option");
        (void)close(s);
        return -1;
    }
    /* Bind the socket. */
    ret = bind(s, ai->ai_addr, ai->ai_addrlen);
    if ( ret < 0 ) {
        /* Error on binding the socket. */
        error_sys_msg(errstr.server, "Binding socket");
        (void)close(s);
        return -1;
    }

    if ( SOCK_STREAM == ai->ai_socktype ) {
        /* Listen the socket. */
        ret = listen(s, MAXSOCKS);
        if ( ret < 0 ) {
            /* Error on listening the socket. */
            error_sys_msg(errstr.server, "Listening socket");
            (void)close(s);
            return -1;
        }
    }

#if ENABLE_SSL
    if ( NULL != sslparams ) {
        /* Setup SSL */
        meth = SSLv3_server_method();
        ctx = SSL_CTX_new(meth);
        if ( NULL == ctx ) {
            /* Error */
            (void)close(s);
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            error_warn("%s", errbuf);
            return -1;
        }
        if ( SSL_CTX_use_PrivateKey_file(ctx, sslparams->key.file,
                                         sslparams->key.type) <= 0 ) {
            /* Error */
            (void)close(s);
            SSL_CTX_free(ctx);
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            error_warn("%s (key: %s)", errbuf, sslparams->key.file);
            return -1;
        }
        if ( SSL_CTX_use_certificate_file(ctx, sslparams->cert.file,
                                          sslparams->cert.type) <= 0 ) {
            /* Error */
            (void)close(s);
            SSL_CTX_free(ctx);
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            error_warn("%s (cert: %s)", errbuf, sslparams->cert.file);
            return -1;
        }

        /* Allocate blocks for server sockets. */
        srvs = realloc(srv->svs,
                       sizeof(struct server_instance) * (srv->nsvs + 1));
        if ( NULL == srvs ) {
            (void)close(s);
            SSL_CTX_free(ctx);
            assert( ENOMEM == errno );
            /* Memory error. */
            error_msg(errstr.nomem);
            return -1;
        }
        /* Append a socket. */
        srvs[srv->nsvs].sock = s;
        srvs[srv->nsvs].pollidx = -1;
        srvs[srv->nsvs].socktype = ai->ai_socktype;
        srvs[srv->nsvs].proto = ai->ai_protocol;
        srvs[srv->nsvs].mpm = mpm;
        srvs[srv->nsvs].sslctx = ctx;
        srvs[srv->nsvs].negotiate = _ssl_negotiate;
        srvs[srv->nsvs].read = _ssl_read;
        srvs[srv->nsvs].write = _ssl_write;
        srvs[srv->nsvs].shutdown = _ssl_shutdown;
        (void)memcpy(&(srvs[srv->nsvs].handlers), handlers,
                     sizeof(struct server_session_handlers));
        srv->svs = srvs;
        srv->nsvs++;
    } else {
        /* Allocate blocks for server sockets. */
        srvs = realloc(srv->svs,
                       sizeof(struct server_instance) * (srv->nsvs + 1));
        if ( NULL == srvs ) {
            (void)close(s);
            assert( ENOMEM == errno );
            /* Memory error. */
            error_msg(errstr.nomem);
            return -1;
        }
        /* Append a socket. */
        srvs[srv->nsvs].sock = s;
        srvs[srv->nsvs].pollidx = -1;
        srvs[srv->nsvs].socktype = ai->ai_socktype;
        srvs[srv->nsvs].proto = ai->ai_protocol;
        srvs[srv->nsvs].mpm = mpm;
        srvs[srv->nsvs].sslctx = NULL;
        srvs[srv->nsvs].negotiate = _negotiate;
        srvs[srv->nsvs].read = _read;
        srvs[srv->nsvs].write = _write;
        srvs[srv->nsvs].shutdown = _shutdown;
        (void)memcpy(&(srvs[srv->nsvs].handlers), handlers,
                     sizeof(struct server_session_handlers));
        srv->svs = srvs;
        srv->nsvs++;
    }
#else
    /* Allocate blocks for server sockets. */
    srvs = realloc(srv->svs,
                   sizeof(struct server_instance) * (srv->nsvs + 1));
    if ( NULL == srvs ) {
        (void)close(s);
        assert( ENOMEM == errno );
        /* Memory error. */
        error_msg(errstr.nomem);
        return -1;
    }
    /* Append a socket. */
    srvs[srv->nsvs].sock = s;
    srvs[srv->nsvs].pollidx = -1;
    srvs[srv->nsvs].socktype = ai->ai_socktype;
    srvs[srv->nsvs].proto = ai->ai_protocol;
    srvs[srv->nsvs].mpm = mpm;
    srvs[srv->nsvs].negotiate = _negotiate;
    srvs[srv->nsvs].read = _read;
    srvs[srv->nsvs].write = _write;
    srvs[srv->nsvs].shutdown = _shutdown;
    (void)memcpy(&(srvs[srv->nsvs].handlers), handlers,
                 sizeof(struct server_session_handlers));
    srv->svs = srvs;
    srv->nsvs++;
#endif

    return 0;
}

/*
 * Close server sockets.
 *
 * RETURN VALUES
 *      On successful completion, the function server_close() returns 0.
 *      Otherwise the return value is non-zero.
 */
int
server_close(struct server *srv)
{
    int i;

    /* Close all server sockets. */
    for ( i = 0; i < srv->nsvs; i++ ) {
#if ENABLE_SSL
        if ( NULL != srv->svs[i].sslctx ) {
            /* Free SSL context and SSL structure */
            SSL_CTX_free(srv->svs[i].sslctx);
        }
#endif
        (void)close(srv->svs[i].sock);
    }
    free(srv->svs);
    srv->svs = NULL;
    srv->nsvs = 0;

    return 0;
}

/*
 * Accept client socket.
 *
 * RETURN VALUES
 *      The function _accept_stream() returns 0 on successful completion.
 *      Otherwise the return value is -1.
 */
static int
_session_stream(struct server *srv, struct server_instance *si, void *udata)
{
    int ret;
    int cs;
    struct server_session sess;
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
#if ENABLE_SSL
    SSL *ssl;
    char errbuf[128];
#endif

    /* Accept */
    caddrlen = sizeof(caddr);
    /* Note: "accept" never blocks when "select" returns. */
    cs = accept(si->sock, (struct sockaddr *)&caddr, &caddrlen);
    if ( cs < 0 ) {
        /* Cannot accept the client socket. */
        return -1;
    }
    /* Create session */
    sess.sock = cs;
    sess.caddr = caddr;
    sess.caddrlen = caddrlen;

#if ENABLE_SSL
    if ( NULL != si->sslctx ) {
        /* Set SSL context */
        ssl = SSL_new(si->sslctx);
        if ( NULL == ssl ) {
            /* Error */
            (void)close(cs);
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            error_warn("%s", errbuf);
            return -1;
        }
        if ( SSL_set_fd(ssl, sess.sock) <= 0 ) {
            /* Error */
            (void)close(cs);
            SSL_free(ssl);
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            error_warn("%s", errbuf);
            return -1;
        }
        sess.ssl = ssl;
    } else {
        sess.ssl = NULL;
    }
#endif

    ret = 0;
    if ( NULL != si->handlers.start ) {
        switch ( si->mpm ) {
        case SERVER_MPM_SINGLE:
            /* Blocking */
            ret = si->handlers.start(srv, si, &sess, udata);
            break;
        case SERVER_MPM_FORK:
            switch ( fork() ) {
            case -1:
                /* Error */
                error_warn("Error on fork.");
                ret = -1;
                break;
            case 0:
                /* Child */
                ret = si->handlers.start(srv, si, &sess, udata);
                _exit(ret);
            default:
                /* Parent, non-blocking */
                ;
            }
            break;
        default:
            /* Unknown MPM */
            error_warn("Unknown MPM.");
            ret = -1;
        }
    } else {
        ret = -1;
    }

    (void)close(cs);

    return ret;
}

/*
 * Receive datagram.
 *
 * RETURN VALUES
 *      The function _recv_dgram() returns 0 on successful completion.
 *      Otherwise the return value is -1.
 */
static __inline__ int
_session_dgram(struct server *srv, struct server_instance *si, void *udata)
{
    int ret;

    ret = 0;
    if ( NULL != si->handlers.start ) {
        switch ( si->mpm ) {
        case SERVER_MPM_SINGLE:
            /* Blocking */
            ret = si->handlers.start(srv, si, NULL, udata);
            break;
        case SERVER_MPM_FORK:
            /* FIXME: Check max # of processes and exit status */
            switch ( fork() ) {
            case -1:
                /* Error */
                error_warn("Error on fork.");
                ret = -1;
                break;
            case 0:
                /* Child */
                ret = si->handlers.start(srv, si, NULL, udata);
                _exit(ret);
            default:
                /* Parent, non-blocking */
                ;
            }
            break;
        default:
            /* Unknown MPM */
            error_warn("Unknown MPM.");
            ret = -1;
        }
    } else {
        ret = -1;
    }

    return ret;
}

static __inline__ int
_server_session(struct server *srv, struct server_instance *si, void *udata)
{
    /* Run server. */
    if ( SOCK_STREAM == si->socktype ) {
        /* Stream */
        if ( 0 != _session_stream(srv, si, udata) ) {
            /* Cannot accpet a client socket or memory error. */
            /* FIXME: Do nothing. */
        }
    } else {
        /* Datagram */
        if ( 0 != _session_dgram(srv, si, udata) ) {
            /* FIXME: Do nothing. */
        }
    }

    return 0;
}

/*
 * Handle server-concerned events.  Check for all events and execute client
 * process.
 *
 * RETURN VALUES
 *      The function _server_events() returns the remaining number of
 *      unhandled events.
 */
static __inline__ int
_server_events(struct server *srv, void *udata, int *events)
{
    int i;
    int ret;

    /* Examine for all server sockets. */
    for ( i = 0; i < srv->nsvs; i++ ) {
        if ( srv->fds[srv->svs[i].pollidx].revents & POLLIN ) {
            ret =_server_session(srv, &(srv->svs[i]), udata);
            (*events)--;
        } else if ( srv->fds[srv->svs[i].pollidx].revents
                    & (POLLERR | POLLHUP | POLLNVAL) ) {
            (*events)--;
        }
        /* Done. */
        if ( 0 == *events ) {
            break;
        }
    }

    return *events;
}

/*
 * Handle trigged events.
 *
 * RETURN VALUES
 *      The function server_event_handler() always returns 0.
 */
int
server_event_handler(struct server *srv, void *udata, int *events)
{
    /* Check for server sockets. */
    (void)_server_events(srv, udata, events);

    return 0;
}

/*
 * Execute the server process.
 *
 * RETURN VALUES
 *      The function server_exec() always returns 0.
 */
int
server_exec(struct server *srv, void *udata)
{
    int i;
    int timeout = 1000;           /* ms */
    int events;
    int ret;
    int stat;
    pid_t cpid;
    struct sigaction sa;
    struct sigaction ssa_term;
    struct sigaction ssa_pipe;

    /* Check the number of sockets */
    if ( srv->nfds <= 0 ) {
        return -1;
    }

    /* SIGTERM handler */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = _sigterm_handler;
    sa.sa_flags = 0;
    ret = sigaction(SIGTERM, &sa, &(ssa_term));
    if ( 0 != ret ) {
        return -1;
    }

    /* Ignore SIGPIPE */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    ret = sigaction(SIGPIPE, &sa, &(ssa_pipe));
    if ( 0 != ret ) {
        /* Restore SIGTERM */
        (void)sigaction(SIGTERM, &(ssa_term), NULL);
        return -1;
    }

    /* Set servers. */
    for ( i = 0; i < srv->nsvs; i++ ) {
        srv->fds[i].fd = srv->svs[i].sock;
        srv->fds[i].events = POLLIN;
        srv->fds[i].revents = 0;
        srv->svs[i].pollidx = i;
    }
    /* Initialize other objects, but no to be polled. */
    for ( ; i < srv->nfds; i++ ) {
        srv->fds[i].fd = -1;
        srv->fds[i].events = 0;
        srv->fds[i].revents = 0;
    }

    /* Main loop */
    for ( ;; ) {
        while ( (cpid = waitpid(-1, &stat, WNOHANG)) > 0 ) {
            /* PID cpid killed w/ WEXITSTATUS(stat) if WIFEXITED */
        }

        if ( rsignal ) {
            /* Wait all child */
            for ( ;; ) {
                cpid = wait(&stat);
                if ( -1 == cpid ) {
                    if ( ECHILD == errno ) {
                        /* No child */
                        break;
                    } else if ( EINTR == errno ) {
                        /* Continue */
                        continue;
                    } else {
                        /* Error, but do nothing... */
                    }
                    usleep(100000);
                } else {
                    /* Do nothing */
                }
            }

            srv->_rsignal = 1;
            /* Termination */
            break;
        }
        rsignal = 0;

        /* Poll events. */
        events = poll(srv->fds, srv->nfds, timeout);
        if ( events < 0 ) {
            /* Interrupt */
            if ( EINTR == errno ) {
                continue;
            }
            /* Error on polling a socket. */
            error_sys_msg("server_process()::poll");
        } else if ( 0 == events ) {
            /* Can be reached when it timeouts.  Do nothing here. */
        } else {
            /* Some events to be handled. */
            ret = server_event_handler(srv, udata, &events);
            /* "ret" must be 0 */
            assert( 0 == ret );
        }
        if ( events > 0 ) {
            error_msg("There are %d event(s) which are not handled.", events);
        }
    }

    /* Unset signals */
    (void)sigaction(SIGTERM, &(ssa_term), NULL);
    (void)sigaction(SIGPIPE, &(ssa_pipe), NULL);

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
