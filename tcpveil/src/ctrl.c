#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ctrl.h"
#include "log.h"

static struct in_addr parse_ip(const char *ip) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1)
        die("invalid peer IP '%s'", ip);
    return a;
}

int ctrl_connect(const char *peer_ip, uint16_t port, volatile sig_atomic_t *stop) {
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = parse_ip(peer_ip),
    };

    for (;;) {
        if (*stop)
            exit(EXIT_FAILURE);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            die("socket: %s", strerror(errno));
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            logmsg("control channel connected to %s:%u", peer_ip, port);
            return fd;
        }
        logmsg("connect to %s:%u failed (%s), retrying in 2s", peer_ip, port, strerror(errno));
        close(fd);
        sleep(2);
    }
}

int ctrl_accept(const char *peer_ip, uint16_t port, volatile sig_atomic_t *stop) {
    struct in_addr peer = parse_ip(peer_ip);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        die("socket: %s", strerror(errno));
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        die("bind port %u: %s", port, strerror(errno));
    if (listen(lfd, 1) < 0)
        die("listen: %s", strerror(errno));
    logmsg("waiting for peer %s on port %u", peer_ip, port);

    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int fd = accept(lfd, (struct sockaddr *)&from, &fl);
        if (fd < 0) {
            if (errno == EINTR && !*stop)
                continue;
            die("accept: %s", strerror(errno));
        }
        if (from.sin_addr.s_addr != peer.s_addr) {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, buf, sizeof(buf));
            logmsg("rejected control connection from unexpected host %s", buf);
            close(fd);
            continue;
        }
        close(lfd);
        logmsg("control channel accepted from %s", peer_ip);
        return fd;
    }
}

int ctrl_write(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int ctrl_read(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n == 0)
            return -1;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

void ctrl_set_timeout(int fd, int sec) {
    struct timeval tv = { .tv_sec = sec };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void *watchdog(void *arg) {
    int fd = (int)(intptr_t)arg;
    uint8_t b;
    for (;;) {
        ssize_t n = read(fd, &b, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            logmsg("control channel closed by peer - stopping (fail closed)");
            exit(EXIT_FAILURE);
        }
    }
}

void ctrl_start_watchdog(int fd) {
    /* Keep SIGINT/SIGTERM for the main thread so they interrupt its recv(). */
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block, &old);

    pthread_t t;
    if (pthread_create(&t, NULL, watchdog, (void *)(intptr_t)fd) != 0)
        die("pthread_create failed");
    pthread_detach(t);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
}
