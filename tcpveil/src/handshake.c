#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "bytes.h"
#include "ctrl.h"
#include "handshake.h"
#include "log.h"

#define DH_GROUP        "ffdhe2048"
#define DH_PUB_LEN      256
#define HS_MAGIC        "SIC1"
#define HS_RANDOM_LEN   32
#define HELLO_PUB_OFF   (4 + 1 + HS_RANDOM_LEN + 2)
#define HELLO_LEN       (HELLO_PUB_OFF + DH_PUB_LEN)
#define CONFIRM_LEN     32
#define HS_TIMEOUT_SEC  10

static EVP_PKEY *dh_generate(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)DH_GROUP, 0),
        OSSL_PARAM_construct_end(),
    };

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
        EVP_PKEY_generate(ctx, &pkey) <= 0)
        die("DH key generation failed");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void dh_export_public(EVP_PKEY *pkey, uint8_t out[DH_PUB_LEN]) {
    unsigned char *pub = NULL;
    size_t n = EVP_PKEY_get1_encoded_public_key(pkey, &pub);

    if (n == 0 || n > DH_PUB_LEN)
        die("DH public key export failed");
    memset(out, 0, DH_PUB_LEN - n);
    memcpy(out + DH_PUB_LEN - n, pub, n);
    OPENSSL_free(pub);
}

static size_t dh_derive(EVP_PKEY *mine, const uint8_t peer_pub[DH_PUB_LEN],
                        uint8_t *secret, size_t secret_cap) {
    EVP_PKEY *peer = EVP_PKEY_new();
    if (!peer || EVP_PKEY_copy_parameters(peer, mine) <= 0 ||
        EVP_PKEY_set1_encoded_public_key(peer, peer_pub, DH_PUB_LEN) <= 0)
        die("cannot load peer DH public key");

    EVP_PKEY_CTX *chk = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (!chk || EVP_PKEY_public_check(chk) != 1)
        die("peer DH public key failed validation");
    EVP_PKEY_CTX_free(chk);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
    size_t len = secret_cap;
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_dh_pad(ctx, 1) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, secret, &len) <= 0)
        die("DH shared secret derivation failed");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return len;
}

static void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0 ||
        EVP_PKEY_derive(ctx, out, &out_len) <= 0)
        die("HKDF failed");
    EVP_PKEY_CTX_free(ctx);
}

static void confirm_mac(const uint8_t key[32], const char *label,
                        const uint8_t th[32], uint8_t out[CONFIRM_LEN]) {
    uint8_t msg[64];
    size_t ll = strlen(label);
    unsigned int outl = CONFIRM_LEN;

    memcpy(msg, label, ll);
    memcpy(msg + ll, th, 32);
    if (!HMAC(EVP_sha256(), key, 32, msg, ll + 32, out, &outl))
        die("HMAC failed");
}

static void build_hello(uint8_t *msg, enum role r, EVP_PKEY *pkey) {
    memcpy(msg, HS_MAGIC, 4);
    msg[4] = (uint8_t)r;
    if (RAND_bytes(msg + 5, HS_RANDOM_LEN) != 1)
        die("RAND_bytes failed");
    put_be16(msg + 5 + HS_RANDOM_LEN, DH_PUB_LEN);
    dh_export_public(pkey, msg + HELLO_PUB_OFF);
}

static void check_hello(const uint8_t *msg, enum role expected) {
    if (memcmp(msg, HS_MAGIC, 4) != 0)
        die("handshake: bad magic from peer");
    if (msg[4] != expected)
        die("handshake: peer has wrong role (both sides configured the same?)");
    if (get_be16(msg + 5 + HS_RANDOM_LEN) != DH_PUB_LEN)
        die("handshake: unexpected DH public key length");
}

void handshake_run(int fd, enum role role, const uint8_t *psk, size_t psk_len,
                   struct session *sess) {
    int initiator = role == ROLE_INITIATOR;
    uint8_t my_hello[HELLO_LEN], peer_hello[HELLO_LEN];
    uint8_t transcript[2 * HELLO_LEN], th[32];
    uint8_t secret[DH_PUB_LEN];
    uint8_t okm[2 * (KEY_LEN + SALT_LEN) + 32];
    uint8_t my_conf[CONFIRM_LEN], peer_conf[CONFIRM_LEN], want_conf[CONFIRM_LEN];

    ctrl_set_timeout(fd, HS_TIMEOUT_SEC);

    EVP_PKEY *dh = dh_generate();
    build_hello(my_hello, role, dh);

    int io_err = initiator
        ? ctrl_write(fd, my_hello, HELLO_LEN) || ctrl_read(fd, peer_hello, HELLO_LEN)
        : ctrl_read(fd, peer_hello, HELLO_LEN) || ctrl_write(fd, my_hello, HELLO_LEN);
    if (io_err)
        die("handshake: I/O error during HELLO exchange");
    check_hello(peer_hello, initiator ? ROLE_RESPONDER : ROLE_INITIATOR);

    memcpy(transcript, initiator ? my_hello : peer_hello, HELLO_LEN);
    memcpy(transcript + HELLO_LEN, initiator ? peer_hello : my_hello, HELLO_LEN);
    if (!EVP_Digest(transcript, sizeof(transcript), th, NULL, EVP_sha256(), NULL))
        die("SHA-256 failed");

    size_t slen = dh_derive(dh, peer_hello + HELLO_PUB_OFF, secret, sizeof(secret));
    EVP_PKEY_free(dh);

    uint8_t info[8 + 32];
    memcpy(info, "SIC1 key", 8);
    memcpy(info + 8, th, 32);
    hkdf_sha256(psk, psk_len, secret, slen, info, sizeof(info), okm, sizeof(okm));
    OPENSSL_cleanse(secret, sizeof(secret));

    struct dir_keys i2r, r2i;
    const uint8_t *p = okm;
    memcpy(i2r.key, p, KEY_LEN);   p += KEY_LEN;
    memcpy(i2r.salt, p, SALT_LEN); p += SALT_LEN;
    memcpy(r2i.key, p, KEY_LEN);   p += KEY_LEN;
    memcpy(r2i.salt, p, SALT_LEN); p += SALT_LEN;
    const uint8_t *confirm_key = p;

    confirm_mac(confirm_key, initiator ? "initiator done" : "responder done", th, my_conf);
    confirm_mac(confirm_key, initiator ? "responder done" : "initiator done", th, want_conf);

    if (ctrl_write(fd, my_conf, CONFIRM_LEN) || ctrl_read(fd, peer_conf, CONFIRM_LEN))
        die("handshake: I/O error during key confirmation");
    if (CRYPTO_memcmp(peer_conf, want_conf, CONFIRM_LEN) != 0)
        die("handshake: key confirmation failed (PSK mismatch or MITM)");

    session_init(sess, initiator ? &i2r : &r2i, initiator ? &r2i : &i2r);
    OPENSSL_cleanse(okm, sizeof(okm));
    OPENSSL_cleanse(&i2r, sizeof(i2r));
    OPENSSL_cleanse(&r2i, sizeof(r2i));

    ctrl_set_timeout(fd, 0);
    logmsg("secure session established (DH %s, PSK-authenticated, AES-256-GCM)", DH_GROUP);
}
