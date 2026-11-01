#include <string.h>

#include <openssl/crypto.h>

#include "bytes.h"
#include "log.h"
#include "session.h"

void session_init(struct session *s, const struct dir_keys *tx, const struct dir_keys *rx) {
    memset(s, 0, sizeof(*s));
    s->tx = *tx;
    s->rx = *rx;

    s->enc = EVP_CIPHER_CTX_new();
    s->dec = EVP_CIPHER_CTX_new();
    if (!s->enc || !s->dec ||
        EVP_EncryptInit_ex(s->enc, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(s->enc, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(s->enc, NULL, NULL, s->tx.key, NULL) != 1 ||
        EVP_DecryptInit_ex(s->dec, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(s->dec, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(s->dec, NULL, NULL, s->rx.key, NULL) != 1)
        die("AES-GCM context setup failed");
}

void session_free(struct session *s) {
    EVP_CIPHER_CTX_free(s->enc);
    EVP_CIPHER_CTX_free(s->dec);
    OPENSSL_cleanse(s, sizeof(*s));
}

static void make_nonce(uint8_t nonce[NONCE_LEN], const uint8_t salt[SALT_LEN], uint64_t ctr) {
    memcpy(nonce, salt, SALT_LEN);
    put_be64(nonce + SALT_LEN, ctr);
}

static int replay_check(const struct session *s, uint64_t ctr) {
    if (ctr == 0)
        return -1;
    if (ctr > s->rx_top)
        return 0;
    uint64_t diff = s->rx_top - ctr;
    if (diff >= REPLAY_WINDOW)
        return -1;
    return (s->rx_bitmap & (1ULL << diff)) ? -1 : 0;
}

static void replay_update(struct session *s, uint64_t ctr) {
    if (ctr > s->rx_top) {
        uint64_t shift = ctr - s->rx_top;
        s->rx_bitmap = shift >= REPLAY_WINDOW ? 0 : s->rx_bitmap << shift;
        s->rx_bitmap |= 1;
        s->rx_top = ctr;
    } else {
        s->rx_bitmap |= 1ULL << (s->rx_top - ctr);
    }
}

int session_seal(struct session *s, const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t len, uint8_t *out) {
    if (s->tx_ctr == UINT64_MAX) {
        logmsg("nonce counter exhausted - restart to rekey");
        return -1;
    }
    /* Counter only increases and keys differ per direction: a nonce is never reused. */
    uint64_t ctr = ++s->tx_ctr;

    uint8_t nonce[NONCE_LEN];
    make_nonce(nonce, s->tx.salt, ctr);
    uint8_t *ctr_field = out + len;
    uint8_t *tag = ctr_field + CTR_LEN;

    EVP_CIPHER_CTX *c = s->enc;
    int outl;
    if (EVP_EncryptInit_ex(c, NULL, NULL, NULL, nonce) != 1 ||
        EVP_EncryptUpdate(c, NULL, &outl, aad, (int)aad_len) != 1 ||
        EVP_EncryptUpdate(c, out, &outl, pt, (int)len) != 1 ||
        EVP_EncryptFinal_ex(c, out + outl, &outl) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        logmsg("encryption failed");
        return -1;
    }
    put_be64(ctr_field, ctr);
    return 0;
}

enum open_result session_open(struct session *s, const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t in_len, uint8_t *pt) {
    size_t len = in_len - TRAILER_LEN;
    const uint8_t *ctr_field = in + len;
    const uint8_t *tag = ctr_field + CTR_LEN;
    uint64_t ctr = get_be64(ctr_field);

    if (replay_check(s, ctr) != 0) {
        logdbg("drop: replayed/old counter %llu", (unsigned long long)ctr);
        return OPEN_REPLAY;
    }

    uint8_t nonce[NONCE_LEN];
    make_nonce(nonce, s->rx.salt, ctr);

    EVP_CIPHER_CTX *c = s->dec;
    int outl;
    if (EVP_DecryptInit_ex(c, NULL, NULL, NULL, nonce) != 1 ||
        EVP_DecryptUpdate(c, NULL, &outl, aad, (int)aad_len) != 1 ||
        EVP_DecryptUpdate(c, pt, &outl, in, (int)len) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(c, pt + outl, &outl) != 1) {
        logdbg("drop: authentication tag mismatch (ctr %llu)", (unsigned long long)ctr);
        return OPEN_AUTH_FAIL;
    }
    replay_update(s, ctr);
    return OPEN_OK;
}
