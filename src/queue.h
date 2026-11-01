#ifndef TCPVEIL_QUEUE_H
#define TCPVEIL_QUEUE_H

#include <signal.h>
#include <stdint.h>

#include "packet.h"
#include "session.h"

struct queue_config {
    uint16_t queue_num;
    unsigned lan_idx, wan_idx;
};

void queue_run(const struct queue_config *qc, struct session *sess,
               struct packet_stats *st, volatile sig_atomic_t *stop);

#endif
