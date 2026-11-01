#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "ctrl.h"
#include "handshake.h"
#include "log.h"
#include "packet.h"
#include "psk.h"
#include "queue.h"
#include "session.h"

#define DEFAULT_PORT    5555

struct config {
    enum role role;
    const char *peer_ip;
    uint16_t port;
    const char *lan_if, *wan_if;
    uint16_t queue_num;
    const char *key_file;
};

static volatile sig_atomic_t stop_flag;

static void on_signal(int sig) {
    (void)sig;
    stop_flag = 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -r initiator|responder -p PEER_IP -l LAN_IF -w WAN_IF -K KEY_FILE\n"
        "          [-P PORT] [-q QUEUE] [-v]\n"
        "  -r  role: Device1 = initiator, Device2 = responder\n"
        "  -p  WAN IP address of the peer device\n"
        "  -l  interface toward the local host (PC1 / PC2)\n"
        "  -w  interface toward the peer device\n"
        "  -K  file with the pre-shared key (>= %d bytes, chmod 600), same on both devices\n"
        "  -P  control channel TCP port (default %d)\n"
        "  -q  NFQUEUE number (default 0)\n"
        "  -v  verbose per-packet logging\n",
        prog, PSK_MIN_LEN, DEFAULT_PORT);
    exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv, struct config *cfg) {
    int opt;
    while ((opt = getopt(argc, argv, "r:p:P:l:w:q:K:vh")) != -1) {
        switch (opt) {
        case 'r':
            if (!strcmp(optarg, "initiator"))      cfg->role = ROLE_INITIATOR;
            else if (!strcmp(optarg, "responder")) cfg->role = ROLE_RESPONDER;
            else usage(argv[0]);
            break;
        case 'p': cfg->peer_ip = optarg; break;
        case 'P': cfg->port = (uint16_t)atoi(optarg); break;
        case 'l': cfg->lan_if = optarg; break;
        case 'w': cfg->wan_if = optarg; break;
        case 'q': cfg->queue_num = (uint16_t)atoi(optarg); break;
        case 'K': cfg->key_file = optarg; break;
        case 'v': log_verbose = 1; break;
        default:  usage(argv[0]);
        }
    }
    if (!cfg->role || !cfg->peer_ip || !cfg->lan_if || !cfg->wan_if || !cfg->key_file)
        usage(argv[0]);
}

int main(int argc, char **argv) {
    struct config cfg = { .port = DEFAULT_PORT };
    parse_args(argc, argv, &cfg);

    static uint8_t psk[PSK_MAX_LEN];
    size_t psk_len = psk_load(cfg.key_file, psk);

    struct queue_config qc = {
        .queue_num = cfg.queue_num,
        .lan_idx = if_nametoindex(cfg.lan_if),
        .wan_idx = if_nametoindex(cfg.wan_if),
    };
    if (!qc.lan_idx || !qc.wan_idx)
        die("unknown interface (lan=%s wan=%s)", cfg.lan_if, cfg.wan_if);

    struct sigaction sa = { .sa_handler = on_signal };   /* no SA_RESTART */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int ctrl_fd = cfg.role == ROLE_INITIATOR
        ? ctrl_connect(cfg.peer_ip, cfg.port, &stop_flag)
        : ctrl_accept(cfg.peer_ip, cfg.port, &stop_flag);

    struct session sess;
    handshake_run(ctrl_fd, cfg.role, psk, psk_len, &sess);
    OPENSSL_cleanse(psk, sizeof(psk));
    ctrl_start_watchdog(ctrl_fd);

    struct packet_stats st = { 0 };
    queue_run(&qc, &sess, &st, &stop_flag);

    logmsg("stats: encrypted=%lu decrypted=%lu auth_fail=%lu replay=%lu malformed=%lu",
           st.enc_ok, st.dec_ok, st.auth_fail, st.replay, st.malformed);

    session_free(&sess);
    close(ctrl_fd);
    return 0;
}
