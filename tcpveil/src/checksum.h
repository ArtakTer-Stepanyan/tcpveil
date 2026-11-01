#ifndef TCPVEIL_CHECKSUM_H
#define TCPVEIL_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

void ip_fix_checksum(uint8_t *ip, size_t ihl);

void tcp_fix_checksum(const uint8_t *ip, uint8_t *tcp, size_t tcp_len);

#endif
