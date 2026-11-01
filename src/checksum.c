#include <netinet/in.h>
#include <string.h>

#include "bytes.h"
#include "checksum.h"

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t len) {
    while (len > 1) {
        sum += get_be16(p);
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void ip_fix_checksum(uint8_t *ip, size_t ihl) {
    ip[10] = ip[11] = 0;
    put_be16(ip + 10, csum_fold(csum_add(0, ip, ihl)));
}

void tcp_fix_checksum(const uint8_t *ip, uint8_t *tcp, size_t tcp_len) {
    uint8_t pseudo[12];

    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    put_be16(pseudo + 10, (uint16_t)tcp_len);

    tcp[16] = tcp[17] = 0;
    uint32_t sum = csum_add(0, pseudo, sizeof(pseudo));
    sum = csum_add(sum, tcp, tcp_len);
    put_be16(tcp + 16, csum_fold(sum));
}
