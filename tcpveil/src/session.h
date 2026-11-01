#ifndef TCPVEIL_SESSION_H
#define TCPVEIL_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#define KEY_LEN         32
#define SALT_LEN        4
#define NONCE_LEN       (SALT_LEN + CTR_LEN)
#define CTR_LEN         8
#define TAG_LEN         16
#define TRAILER_LEN     (CTR_LEN + TAG_LEN)
#define REPLAY_WINDOW   64

struct dir_keys {
    uint8_t key[KEY_LEN];
    uint8_t salt[SALT_LEN];
};

struct session {
    struct dir_keys tx, rx;
    uint64_t tx_ctr;
    uint64_t rx_top;
    uint64_t rx_bitmap;
    EVP_CIPHER_CTX *enc, *dec;
};

enum open_result { OPEN_OK, OPEN_REPLAY, OPEN_AUTH_FAIL };

void session_init(struct session *s, const struct dir_keys *tx, const struct dir_keys *rx);

void session_free(struct session *s);

int session_seal(struct session *s, const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t len, uint8_t *out);

enum open_result session_open(struct session *s, const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t in_len, uint8_t *pt);

#endif
