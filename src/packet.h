#ifndef TCPVEIL_PACKET_H
#define TCPVEIL_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

#define MAX_IP_LEN      65535

struct pkt_view {
    size_t ihl;
    size_t thl;
    size_t tot;
    size_t payload;
};

struct packet_stats {
    unsigned long enc_ok, dec_ok, auth_fail, replay, malformed;
};

int packet_parse(const uint8_t *pkt, size_t len, struct pkt_view *v);

size_t packet_protect(struct session *s, const uint8_t *pkt, const struct pkt_view *v,
                      uint8_t *out, struct packet_stats *st);
size_t packet_unprotect(struct session *s, const uint8_t *pkt, const struct pkt_view *v,
                        uint8_t *out, struct packet_stats *st);

#endif
