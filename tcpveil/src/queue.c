#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "log.h"
#include "queue.h"

struct queue_ctx {
    const struct queue_config *qc;
    struct session *sess;
    struct packet_stats *st;
};

static uint8_t out_pkt[MAX_IP_LEN];

static int on_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfa, void *data) {
    (void)nfmsg;
    struct queue_ctx *ctx = data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
        return 0;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *pkt;
    int len = nfq_get_payload(nfa, &pkt);
    uint32_t indev = nfq_get_indev(nfa);

    struct pkt_view v;
    size_t out_len = 0;

    if (len <= 0 || packet_parse(pkt, (size_t)len, &v) != 0)
        ctx->st->malformed++;
    else if (indev == ctx->qc->lan_idx)
        out_len = packet_protect(ctx->sess, pkt, &v, out_pkt, ctx->st);
    else if (indev == ctx->qc->wan_idx)
        out_len = packet_unprotect(ctx->sess, pkt, &v, out_pkt, ctx->st);

    if (out_len == 0)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    logdbg("%s pkt id=%u payload=%zu -> ip_len=%zu",
           indev == ctx->qc->lan_idx ? "ENC" : "DEC", id, v.payload, out_len);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)out_len, out_pkt);
}

void queue_run(const struct queue_config *qc, struct session *sess,
               struct packet_stats *st, volatile sig_atomic_t *stop) {
    struct queue_ctx ctx = { .qc = qc, .sess = sess, .st = st };

    struct nfq_handle *h = nfq_open();
    if (!h)
        die("nfq_open failed (are you root?)");
    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0)
        die("nfq_bind_pf failed");

    struct nfq_q_handle *qh = nfq_create_queue(h, qc->queue_num, &on_packet, &ctx);
    if (!qh)
        die("nfq_create_queue(%u) failed - is another instance running?", qc->queue_num);
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
        die("nfq_set_mode failed");
    nfq_set_queue_maxlen(qh, 4096);

    int fd = nfq_fd(h);
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    logmsg("processing TCP traffic: queue=%u lan_idx=%u wan_idx=%u",
           qc->queue_num, qc->lan_idx, qc->wan_idx);

    static uint8_t buf[0x20000] __attribute__((aligned(8)));
    while (!*stop) {
        ssize_t rv = recv(fd, buf, sizeof(buf), 0);
        if (rv < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOBUFS) {
                logmsg("warning: NFQUEUE overrun, packets lost");
                continue;
            }
            logmsg("recv: %s", strerror(errno));
            break;
        }
        nfq_handle_packet(h, (char *)buf, (int)rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
}
