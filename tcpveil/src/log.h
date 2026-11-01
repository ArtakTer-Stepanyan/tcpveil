#ifndef TCPVEIL_LOG_H
#define TCPVEIL_LOG_H

extern int log_verbose;

void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

#define logdbg(...) do { if (log_verbose) logmsg(__VA_ARGS__); } while (0)

#endif
