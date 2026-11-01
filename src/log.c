#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>

#include "log.h"

int log_verbose;

static void vlog(const char *prefix, const char *fmt, va_list ap) {
    fprintf(stderr, "[tcpveil] %s", prefix);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog("", fmt, ap);
    va_end(ap);
}

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog("FATAL: ", fmt, ap);
    va_end(ap);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}
