#ifndef TCPVEIL_CTRL_H
#define TCPVEIL_CTRL_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

int ctrl_connect(const char *peer_ip, uint16_t port, volatile sig_atomic_t *stop);

int ctrl_accept(const char *peer_ip, uint16_t port, volatile sig_atomic_t *stop);

int ctrl_write(int fd, const void *buf, size_t len);
int ctrl_read(int fd, void *buf, size_t len);

void ctrl_set_timeout(int fd, int sec);

void ctrl_start_watchdog(int fd);

#endif
