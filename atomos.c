/*_
 * Copyright 2011 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: nsd.c,v f045f3d6e083 2011/02/12 10:50:28 Hirochika $ */

#include "config.h"

#include "dns.h"
#include "zone.h"
#include "selector.h"
#include "common/daemon.h"
#include "common/pid_output.h"
#include "common/log.h"
#include "common/error.h"
#include "common/server.h"
#include "scfg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#if TARGET_LINUX
#include <linux/limits.h>          /* For PATH_MAX */
#else
#include <sys/syslimits.h>      /* For PATH_MAX */
#endif
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>              /* getservbyname, servent */
#include <pwd.h>
/* Socket */
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>

#define UDP_BUFSIZE 65536

extern int error_syslog;


/*
 * Prototype declarations
 */
int
session_stream(struct server *, struct server_instance *,
               struct server_session *, void *);
int
session_dgram(struct server *, struct server_instance *,
              struct server_session *, void *);


/*
 * Session manager for TCP connection
 */
int
session_stream(struct server *srv, struct server_instance *si,
               struct server_session *sess, void *udata)
{
    ssize_t n;
    ssize_t nr;
    ssize_t nw;
    ssize_t len;
    uint16_t b16;
    unsigned char buf[UDP_BUFSIZE];
    struct dns_message *qmsg;
    struct dns_message *rmsg;
    char *prmsg;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    struct dns *dns;
    struct timeval timeout;

    /* Assertion */
    if ( NULL == sess ) {
        return -1;
    }

    dns = (struct dns *)udata;

    /* Set timeout */
    if ( dns->cfg->timeout > 0 ) {
        timeout.tv_sec = (time_t)dns->cfg->timeout;
        timeout.tv_usec = (suseconds_t)((dns->cfg->timeout
                                         - (time_t)dns->cfg->timeout)
                                        * 1000000);
        if ( 0 != setsockopt(sess->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                             sizeof(struct timeval)) ) {
            /* Error */
            (void)shutdown(sess->sock, SHUT_RDWR);
            return -1;
        }
    }
    /* Set non-blocking mode to the socket. */
    /*(void)fcntl(sess->sock, F_SETFL, O_NONBLOCK);*/

    /* Get client's IP address. */
    if ( 0 == getnameinfo((struct sockaddr *)&(sess->caddr), sess->caddrlen,
                          host, sizeof(host), service, sizeof(service),
                          NI_NUMERICHOST | NI_NUMERICSERV) ) {
    } else {
        (void)shutdown(sess->sock, SHUT_RDWR);
        return -1;
    }

    /* Receive length */
    nr = recv(sess->sock, &b16, 2, 0);
    if ( nr != 2 ) {
        (void)shutdown(sess->sock, SHUT_RDWR);
        return -1;
    }
    len = ntohs(b16);

    /* Receive */
    nr = 0;
    while ( len > nr ) {
        n = recv(sess->sock, buf + nr, len - nr, 0);
        if ( n == 0 ) {
            (void)shutdown(sess->sock, SHUT_RDWR);
            return -1;
        }
        nr += n;
    }

    /* Parse query */
    qmsg = dns_parse_query(buf, nr);
    if ( NULL == qmsg ) {
        /* Server error */
        (void)shutdown(sess->sock, SHUT_RDWR);
        return -1;
    }

    /* Get the response */
    rmsg = dns_selector_query(host, qmsg, dns->cfg);
    if ( NULL == rmsg ) {
        /* Server error */
        dns_message_delete(qmsg);
        (void)shutdown(sess->sock, SHUT_RDWR);
        return -1;
    }

    /* Build response packet */
    len = dns_build_response(rmsg, buf, sizeof(buf));
    b16 = htons((uint16_t)len);
    if ( 2 != send(sess->sock, &b16, 2, 0) ) {
        (void)shutdown(sess->sock, SHUT_RDWR);
        return -1;
    }
    nw = 0;
    while ( len > nw ) {
        n = send(sess->sock, buf + nw, len - nw, 0);
        if ( n == 0 ) {
            (void)shutdown(sess->sock, SHUT_RDWR);
            return -1;
        }
        nw += n;
    }

    /* Logging */
    prmsg = dns_printable_message(rmsg);
    if ( NULL != prmsg ) {
        (void)log_write(dns->log, "[%s]:%s %s", host, service, prmsg);
        free(prmsg);
    } else {
        (void)log_write(dns->log, "[%s]:%s", host, service);
    }

    /* Release memory */
    dns_message_delete(rmsg);
    dns_message_delete(qmsg);

    (void)shutdown(sess->sock, SHUT_RDWR);

    return 0;
}

/*
 * Session manager for UDP packets
 *      Read datagram, i.e., called once per DNS request
 */
int
session_dgram(struct server *srv, struct server_instance *si,
              struct server_session *sess, void *udata)
{
    ssize_t nr;
    ssize_t nw;
    unsigned char buf[UDP_BUFSIZE];
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
    struct dns_message *qmsg;
    struct dns_message *rmsg;
    char *prmsg;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    struct dns *dns;
    size_t maxsize;

    /* Assertion */
    if ( NULL != sess ) {
        return -1;
    }

    dns = (struct dns *)udata;

    /* Receive */
    caddrlen = sizeof(caddr);
    nr = recvfrom(si->sock, buf, sizeof(buf), 0, (struct sockaddr *)&caddr,
                  &caddrlen);

    /* Get client's IP address. */
    if ( 0 == getnameinfo(
             (struct sockaddr *)&caddr, caddrlen, host, sizeof(host),
             service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) ) {
    } else {
        return -1;
    }

    /* Parse query */
    qmsg = dns_parse_query(buf, nr);
    if ( NULL == qmsg ) {
        /* Server error */
        return -1;
    }

    /* Get UDP payload size */
    maxsize = dns_get_payload_size(qmsg);
    if ( maxsize > sizeof(buf) ) {
        maxsize = sizeof(buf);
    }

    /* Get the response */
    rmsg = dns_selector_query(host, qmsg, dns->cfg);
    if ( NULL == rmsg ) {
        /* Server error */
        dns_message_delete(qmsg);
        return -1;
    }

    /* Build response packet */
    nw = dns_build_response(rmsg, buf, maxsize);
    if ( nw != sendto(si->sock, buf, nw, 0, (struct sockaddr *)&caddr,
                      caddrlen) ) {
        /* Error */
        dns_message_delete(rmsg);
        dns_message_delete(qmsg);
        return -1;
    }

    /* Logging */
    prmsg = dns_printable_message(rmsg);
    if ( NULL != prmsg ) {
        (void)log_write(dns->log, "[%s]:%s %s", host, service, prmsg);
        free(prmsg);
    } else {
        (void)log_write(dns->log, "[%s]:%s", host, service);
    }

    /* Release memory */
    dns_message_delete(rmsg);
    dns_message_delete(qmsg);

    return 0;
}

/*
 * Print usage
 */
void
usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n"
            "  --chroot            Change root to the configured directory\n"
            "  -f, --config-file=config_file\n"
            "                      The configuration file\n", prog);
    exit(EXIT_FAILURE);
}


/*
 * main function
 */
int
main(int argc, char *const argv[])
{
    struct passwd *pwd;
    int ret;
    pid_t pid;
    scfg_t *cfg;
    char *tgt;
    char *tmp;
    struct dns dns;
    struct server *srv;
    char *config_file = NULL;
    int ch;
    int chroot_flag;

    struct option longopts[] = {
        { "config-file", required_argument, NULL, 'f' },
        { "chroot", no_argument, &chroot_flag, 1 },
        { NULL, 0, NULL, 0 }
    };

    struct server_session_handlers tcp_sess = {
        .timeout = NULL,
        .start = session_stream,
    };
    struct server_session_handlers udp_sess = {
        .timeout = NULL,
        .start = session_dgram,
    };


    /* Parse arguments */
    opterr = 0;
    chroot_flag = 0;
    while ( (ch = getopt_long(argc, argv, "f:", longopts, NULL)) != -1 ) {
        switch ( ch ) {
        case 'f':
            config_file = strdup(optarg);
            if ( NULL == config_file ) {
                error_quit("Abort: Memorry error.");
            }
            break;
        case 0:
            break;
        default:
            usage(argv[0]);
        }
    }
    /* Default parameters */
    if ( NULL == config_file ) {
        config_file = strdup(AMETHYST_DEFAULT_CONFIG_FILE);
        if ( NULL == config_file ) {
            error_quit("Abort: Memorry error.");
        }
    }


    /* Initialize dns daemon instance */
    dns.prog = strdup(argv[0]);
    if ( NULL == dns.prog ) {
        error_quit("Abort: Memorry error.");
    }
    dns.log = NULL;

    /* Parse configuration file */
    cfg = scfg_parse(config_file);
    if ( NULL == cfg ) {
        error_quit("Cannot parse configuration file: %s", config_file);
    }
    dns.cfg = dns_cfg_new(cfg);
    if ( NULL == dns.cfg ) {
        error_quit("Cannot parse configuration file: %s", config_file);
    }
    scfg_release(cfg);

    /* Check pid file and whether it is alive. */
    pid = pid_output_read(PATH_ATOMOS_PID);
    if ( pid >= 0 ) {
        ret = kill(pid, 0);
        if ( 0 == ret ) {
            error_quit("Abort: Process %d is still alive.", pid);
        }
    }

    /* Open log file */
    if ( NULL != dns.cfg->logfile ){
        dns.log = log_file_open(dns.cfg->logfile);
        if ( NULL == dns.log ) {
            error_quit("Abort: Cannot open log file %s.", dns.cfg->logfile);
        }
    }

    /* Enable syslog */
    error_enable_syslog();

    /* Daemonize; the first argument should be 1 if the pid file is a relative
       path */
    ret = daemon_ng(0, 0);
    if ( 0 != ret ) {
        error_quit("Abort: Failed on daemonizing.");
    }

    /* Output pid */
    pid = pid_output(PATH_ATOMOS_PID);
    if ( pid < 0 ) {
        error_quit("Abort: Failed on pid output.");
    }

    /* Change directory */
    ret = chdir(dns.cfg->directory);
    if ( 0 != ret ) {
        error_quit("Abort: Failed on chdir.");
    }
    if ( chroot_flag ) {
        /* Change root */
        ret = chroot(dns.cfg->directory);
        if ( 0 != ret ) {
            error_quit("Abort: Failed on chroot.");
        }
    }

    /* Initialize server instance */
    srv = server_init(NULL);
    if ( NULL == srv ) {
        error_quit("Abort: Failed on initializing the server.");
    }

    /* Open server sockets */
    tmp = dns.cfg->listens;
    while ( '\0' != *tmp ) {
        if ( 0 == strcmp("*", tmp) ) {
            tgt = NULL;
            tmp += strlen(tmp) + 1;
        } else {
            tgt = tmp;
            tmp += strlen(tmp) + 1;
        }

        /* Open UDP server instance */
        if ( server_udp_open(srv, tgt, "domain", SERVER_MPM_SINGLE, &udp_sess)
             < 0 ) {
            /* Error */
            (void)server_close(srv);
            (void)server_release(srv);
            return EXIT_FAILURE;
        }

        /* Open TCP server instance */
        if ( server_tcp_open(srv, tgt, "domain", SERVER_MPM_FORK, &tcp_sess)
             < 0 ) {
            /* Error */
            (void)server_close(srv);
            (void)server_release(srv);
            return EXIT_FAILURE;
        }
    }

    /* Get UID */
    if ( NULL == (pwd = getpwnam(ATOMOS_DEFAULT_USER)) ) {
        (void)server_release(srv);
        return EXIT_FAILURE;
    }
    /* Set the uid */
    if ( 0 != setuid(pwd->pw_uid) ) {
        (void)server_release(srv);
        return EXIT_FAILURE;
    }
    /* Renounce the privilege */
    if ( 0 != seteuid(getuid()) ) {
        (void)server_release(srv);
        return EXIT_FAILURE;
    }

#if DEBUG
    /* Print out the user information */
    error_notice("DEBUG: executing as "
                 "name=%s, UID=%d, GID=%d, HOME=%s, shell=%s\n",
                 pwd->pw_name, pwd->pw_uid, pwd->pw_gid, pwd->pw_dir,
                 pwd->pw_shell);
#endif

    /* Execute the server */
    ret = server_exec(srv, &dns);
    if ( 0 != ret ) {
        error_quit("Abort: Failed on executing.");
    }

    log_close(dns.log);
    error_msg("Abort: Exit normally.");


    /* Close and release */
    (void)server_close(srv);
    (void)server_release(srv);

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
