#ifndef TCPVEIL_HANDSHAKE_H
#define TCPVEIL_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

enum role { ROLE_INITIATOR = 1, ROLE_RESPONDER = 2 };

void handshake_run(int fd, enum role role, const uint8_t *psk, size_t psk_len,
                   struct session *sess);

#endif
