/*_
 * Copyright 2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "error.h"
#include "sslserver.h"
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

/* OpenSSL */
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


/* Signal result */
static int rsignal = 0;

static void
_sigterm_handler(int signo)
{
    rsignal = 1;
}

/*
 * Initialize server.
 *
 * RETURN VALUES
 *      On successful completion sslserver_init() returns 0.  Otherwise, NULL is
 *      returned.
 */
struct sslserver *
sslserver_init(struct sslserver *srv)
{
    /* Initialize SSL */
    /*srand((unsigned)time(NULL));*/
    SSL_load_error_strings();
    SSL_library_init();

    /* Need to allocate? */
    if ( NULL == srv ) {
        srv = malloc(sizeof(struct sslserver));
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
    srv->nfds = MAXSSLSOCKS;
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
sslserver_release(struct sslserver *srv)
{
    /* Free all sockets */
    free(srv->fds);
    /* Need to free memory? */
    if ( srv->_need_to_free ) {
        free(srv);
    }

    /* Free error strings */
    ERR_free_strings();

    return 0;
}

/*
 * Open server socket.
 *
 * RETURN VALUES
 *      The function sslserver_open() returns the number of sockets opened in
 *      this function.  If an error occurs, the return value is -1.
 */
int
sslserver_open(struct sslserver *srv, const char *host, const char *port,
               int socktype, int proto, int mpm,
               const char *key, const char *cert,
               struct sslserver_session_handlers *handlers)
{
    struct addrinfo hints;
    struct addrinfo *resai;
    struct addrinfo *ai;
    int ret;

    /* Prepare for opening server socket. */
    memset(&hints, 0, sizeof(struct addrinfo));
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
        if ( -1 == sslserver_open_addrinfo(srv, ai, mpm, key, cert,
                                           handlers) ) {
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
 *      The function sslserver_open() returns the number of sockets opened
 *      in this function.  If an error occurs, the return value is -1.
 */
int
sslserver_tcp_open(struct sslserver *srv, const char *host, const char *port,
                   int mpm, const char *key, const char *cert,
                   struct sslserver_session_handlers *handlers)
{
    return sslserver_open(srv, host, port, SOCK_STREAM, IPPROTO_TCP, mpm,
                          key, cert, handlers);
}

/*
 * Open server's addrinfo.
 *
 * RETURN VALUES
 *      The function sslserver_open_addrinfo() returns -1 if an error occurs.
 *      On successful completion, the return value is 0.
 */
int
sslserver_open_addrinfo(struct sslserver *srv, struct addrinfo *ai, int mpm,
                        const char *key, const char *cert,
                        struct sslserver_session_handlers *handlers)
{
    int s;
    int ret;
    int optval;
    struct sslserver_instance *srvs;
    /* For SSL */
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    char errbuf[128];


    /* Check the number of opened sockets. */
    if ( srv->nsvs >= MAXSSLSOCKS ) {
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
        ret = listen(s, MAXSSLSOCKS);
        if ( ret < 0 ) {
            /* Error on listening the socket. */
            error_sys_msg(errstr.server, "Listening socket");
            (void)close(s);
            return -1;
        }
    }

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
    if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        /* Error */
        (void)close(s);
        SSL_CTX_free(ctx);
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        error_warn("%s (key: %s)", errbuf, key);
        return -1;
    }
    if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ) {
        /* Error */
        (void)close(s);
        SSL_CTX_free(ctx);
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        error_warn("%s (cert: %s)", errbuf, cert);
        return -1;
    }
#if 0
    SSL *ssl;
    ssl = SSL_new(ctx);
    if ( NULL == ssl ) {
        /* Error */
        (void)close(s);
        SSL_CTX_free(ctx);
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        error_warn("%s", errbuf);
        return -1;
    }
    if ( SSL_set_fd(ssl, s) <= 0 ) {
        /* Error */
        (void)close(s);
        SSL_CTX_free(ctx);
        SSL_free(ssl);
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        error_warn("%s", errbuf);
        return -1;
    }
#endif

    /* Allocate blocks for server sockets. */
    srvs = realloc(srv->svs,
                   sizeof(struct sslserver_instance) * (srv->nsvs + 1));
    if ( NULL == srvs ) {
        (void)close(s);
        SSL_CTX_free(ctx);
        /* "errno" should be ENOMEM */
        assert( ENOMEM == errno );
        /* Memory error. */
        error_warn(errstr.nomem);
        return -1;
    }

    /* Append a socket. */
    srvs[srv->nsvs].sock = s;
    srvs[srv->nsvs].pollidx = -1;
    srvs[srv->nsvs].socktype = ai->ai_socktype;
    srvs[srv->nsvs].proto = ai->ai_protocol;
    srvs[srv->nsvs].mpm = mpm;
    srvs[srv->nsvs].ctx = ctx;
    (void)memcpy(&(srvs[srv->nsvs].handlers), handlers,
                 sizeof(struct sslserver_session_handlers));
    srv->svs = srvs;

    srv->nsvs++;

    return 0;
}

/*
 * Close server sockets.
 *
 * RETURN VALUES
 *      On successful completion, the function sslserver_close() returns 0.
 *      Otherwise the return value is non-zero.
 */
int
sslserver_close(struct sslserver *srv)
{
    int i;

    /* Close all server sockets. */
    for ( i = 0; i < srv->nsvs; i++ ) {
        /* Free SSL context and SSL structure */
        SSL_CTX_free(srv->svs[i].ctx);
        /*SSL_free(srv->svs[i].ssl);*/
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
_session_stream(struct sslserver *srv, struct sslserver_instance *si,
                void *udata)
{
    int ret;
    int cs;
    struct sslserver_session sess;
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
    char errbuf[128];

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

    SSL *ssl;
    ssl = SSL_new(si->ctx);
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


    ret = 0;
    if ( NULL != si->handlers.start ) {
        switch ( si->mpm ) {
        case SSLSERVER_MPM_SINGLE:
            /* Blocking */
            ret = si->handlers.start(srv, si, &sess, udata);
            break;
        case SSLSERVER_MPM_FORK:
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

static __inline__ int
_server_session(struct sslserver *srv, struct sslserver_instance *si,
                void *udata)
{
    /* Run server. */
    if ( SOCK_STREAM == si->socktype ) {
        /* Stream */
        if ( 0 != _session_stream(srv, si, udata) ) {
            /* Cannot accpet a client socket or memory error. */
            /* FIXME: Do nothing. */
        }
    } else {
        /* FIXME: Do nothing. */
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
_server_events(struct sslserver *srv, void *udata, int *events)
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
 *      The function sslserver_event_handler() always returns 0.
 */
int
sslserver_event_handler(struct sslserver *srv, void *udata, int *events)
{
    /* Check for server sockets. */
    (void)_server_events(srv, udata, events);

    return 0;
}

/*
 * Execute the server process.
 *
 * RETURN VALUES
 *      The function sslserver_exec() always returns 0.
 */
int
sslserver_exec(struct sslserver *srv, void *udata)
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
            ret = sslserver_event_handler(srv, udata, &events);
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
