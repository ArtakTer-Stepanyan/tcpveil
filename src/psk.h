#ifndef TCPVEIL_PSK_H
#define TCPVEIL_PSK_H

#include <stddef.h>
#include <stdint.h>

#define PSK_MIN_LEN     32
#define PSK_MAX_LEN     1024

size_t psk_load(const char *path, uint8_t buf[PSK_MAX_LEN]);

#endif
