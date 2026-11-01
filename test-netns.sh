#!/bin/bash
set -u
cd "$(dirname "$0")"

WORK=$(mktemp -d)
PASS=0 FAIL=0
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    pkill -f "$WORK/tcpveil" 2>/dev/null
    for ns in pc1 dev1 dev2 pc2; do ip netns del $ns 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build"
gcc -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -o "$WORK/tcpveil" src/*.c \
    -lnetfilter_queue -lcrypto -lpthread || { echo "build failed"; exit 1; }
pass "src/*.c compiles with -Wall -Wextra -Werror"

echo "== topology"
for ns in pc1 dev1 dev2 pc2; do ip netns add $ns; ip -n $ns link set lo up; done
link() {
    # temporary names avoid clashing with the host's own interfaces
    ip link add tvtmp0 type veth peer name tvtmp1
    ip link set tvtmp0 netns "$1"; ip -n "$1" link set tvtmp0 name "$2"
    ip link set tvtmp1 netns "$4"; ip -n "$4" link set tvtmp1 name "$5"
    ip -n "$1" addr add "$3" dev "$2"; ip -n "$1" link set "$2" up
    ip -n "$4" addr add "$6" dev "$5"; ip -n "$4" link set "$5" up
}
link pc1  eth0 10.1.0.2/24 dev1 lan0 10.1.0.1/24
link dev1 wan0 10.0.0.1/30 dev2 wan0 10.0.0.2/30
link dev2 lan0 10.2.0.1/24 pc2  eth0 10.2.0.2/24
ip -n pc1 route add default via 10.1.0.1
ip -n pc2 route add default via 10.2.0.1
for ns in pc1 pc2; do ip netns exec $ns ethtool -K eth0 gro off gso off tso off >/dev/null 2>&1; done
ip netns exec dev1 sh setup-device.sh up lan0 wan0 10.2.0.0/24 10.0.0.2 >/dev/null
ip netns exec dev2 sh setup-device.sh up lan0 wan0 10.1.0.0/24 10.0.0.1 >/dev/null

(umask 077; head -c 32 /dev/urandom | base64 > "$WORK/psk.key")
(umask 077; head -c 32 /dev/urandom | base64 > "$WORK/other.key")

start() {
    ip netns exec dev2 "$WORK/tcpveil" -r responder -p 10.0.0.1 -l lan0 -w wan0 -K "$2" \
        > "$WORK/dev2.log" 2>&1 &
    DEV2=$!
    sleep 0.5
    ip netns exec dev1 "$WORK/tcpveil" -r initiator -p 10.0.0.2 -l lan0 -w wan0 -K "$1" \
        > "$WORK/dev1.log" 2>&1 &
    DEV1=$!
    for _ in $(seq 50); do
        grep -q "processing TCP" "$WORK/dev1.log" && grep -q "processing TCP" "$WORK/dev2.log" && return 0
        kill -0 $DEV1 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}
stop() {
    kill $DEV1 $DEV2 2>/dev/null
    wait $DEV1 $DEV2 2>/dev/null
}

cat > "$WORK/tcp.py" <<'EOF'
import hashlib, socket, sys
if sys.argv[1] == "server":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[2]))); s.listen(1); s.settimeout(20)
    c, _ = s.accept(); c.settimeout(20); data = b""
    while True:
        b = c.recv(65536)
        if not b: break
        data += b
    open(sys.argv[3], "wb").write(data)
    c.sendall(hashlib.sha256(data).hexdigest().encode()); c.close()
else:
    c = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=10)
    c.sendall(open(sys.argv[4], "rb").read()); c.shutdown(socket.SHUT_WR)
    print(c.recv(100).decode())
EOF
transfer() {
    ip netns exec "$2" python3 "$WORK/tcp.py" server 7000 "$WORK/recv.bin" &
    local srv=$!
    sleep 0.5
    ip netns exec "$1" timeout 15 python3 "$WORK/tcp.py" client "$3" 7000 "$4" 2>/dev/null
    wait $srv 2>/dev/null
}

echo "== handshake"
if start "$WORK/psk.key" "$WORK/psk.key"; then
    pass "Diffie-Hellman handshake completed on both devices"
else
    fail "handshake did not complete"; cat "$WORK"/dev*.log; exit 1
fi

echo "== data transfer PC1 -> PC2 and PC2 -> PC1"
head -c 3000000 /dev/urandom > "$WORK/data.bin"
want=$(sha256sum "$WORK/data.bin" | cut -d' ' -f1)
[ "$(transfer pc1 pc2 10.2.0.2 "$WORK/data.bin")" = "$want" ] \
    && pass "3 MB PC1->PC2 arrived intact" || fail "PC1->PC2 transfer corrupted or failed"
[ "$(transfer pc2 pc1 10.1.0.2 "$WORK/data.bin")" = "$want" ] \
    && pass "3 MB PC2->PC1 arrived intact" || fail "PC2->PC1 transfer corrupted or failed"

echo "== what the link between the devices carries"
MARKER="TCPVEIL-PLAINTEXT-MARKER-0123456789"
for _ in $(seq 200); do echo "$MARKER"; done > "$WORK/marker.txt"
ip netns exec dev1 tcpdump -i wan0 -U -w "$WORK/wan.pcap" ip and not port 5555 \
    > "$WORK/tcpdump.log" 2>&1 &
TCPDUMP=$!
for _ in $(seq 50); do grep -q "listening on" "$WORK/tcpdump.log" && break; sleep 0.1; done
transfer pc1 pc2 10.2.0.2 "$WORK/marker.txt" >/dev/null
sleep 0.5
kill $TCPDUMP; wait $TCPDUMP 2>/dev/null
cmp -s "$WORK/marker.txt" "$WORK/recv.bin" && pass "PC2 received the original plaintext" \
    || fail "PC2 did not receive the original plaintext"
grep -qa "$MARKER" "$WORK/wan.pcap" && fail "plaintext visible on the WAN link" \
    || pass "plaintext NOT visible on the WAN link"
tcpdump -nr "$WORK/wan.pcap" 2>/dev/null > "$WORK/wan.txt"
n_all=$(wc -l < "$WORK/wan.txt")
n_tcp=$(grep -c "IP 10\.[12]\.0\.2\.[0-9]* > 10\.[12]\.0\.2\.[0-9]*: Flags" "$WORK/wan.txt")
[ "$n_all" -gt 0 ] && [ "$n_all" = "$n_tcp" ] \
    && pass "all $n_all WAN packets are plain TCP between PC1 and PC2 (no UDP, no extra header)" \
    || fail "unexpected packets on WAN ($n_tcp of $n_all are PC1<->PC2 TCP)"
short=$(grep -o "length [0-9]*$" "$WORK/wan.txt" | awk '$2 < 24' | wc -l)
[ "$short" = 0 ] && pass "every WAN packet (incl. SYN/ACK/FIN) carries a counter + tag" \
    || fail "$short WAN packets have no counter + tag"
if [ "$FAIL" != 0 ]; then
    echo "    WAN capture sample:"; head -6 "$WORK/wan.txt" | sed "s/^/      /"
fi

echo "== unprotected traffic is rejected"
# dev1 forwards plaintext, like an attacker injecting packets
ip netns exec dev1 iptables -D FORWARD -i lan0 -o wan0 -p tcp -j NFQUEUE --queue-num 0
before=$(ip netns exec pc2 cat /proc/net/snmp | awk '/^Tcp:/ {f++} f==2 {print $11; exit}')
ip netns exec pc1 timeout 5 python3 -c \
    "import socket; socket.create_connection(('10.2.0.2', 7001), timeout=3)" 2>/dev/null \
    && fail "forged/unprotected SYN reached PC2" \
    || pass "unprotected connection attempt never reached PC2"
after=$(ip netns exec pc2 cat /proc/net/snmp | awk '/^Tcp:/ {f++} f==2 {print $11; exit}')
[ "$before" = "$after" ] && pass "PC2 received no TCP segments, so dev2 dropped the SYN" \
    || fail "PC2 saw the unprotected SYN"
ip netns exec dev1 iptables -A FORWARD -i lan0 -o wan0 -p tcp -j NFQUEUE --queue-num 0
stop
grep -q "stats:" "$WORK/dev2.log" && pass "dev2 shut down cleanly on SIGTERM: $(grep -o 'stats:.*' "$WORK/dev2.log")" \
    || fail "dev2 did not shut down cleanly"

echo "== wrong pre-shared key"
if start "$WORK/psk.key" "$WORK/other.key"; then
    fail "handshake succeeded with different keys"
else
    grep -q "key confirmation failed" "$WORK/dev1.log" "$WORK/dev2.log" \
        && pass "handshake rejected when keys differ" || fail "unexpected error: $(cat "$WORK"/dev*.log)"
fi
stop

echo "== key file checks"
chmod 644 "$WORK/psk.key"
ip netns exec dev1 "$WORK/tcpveil" -r initiator -p 10.0.0.2 -l lan0 -w wan0 -K "$WORK/psk.key" 2>&1 \
    | grep -q "accessible by group/others" && pass "world-readable key file refused" \
    || fail "world-readable key file accepted"
(umask 077; echo short > "$WORK/short.key")
ip netns exec dev1 "$WORK/tcpveil" -r initiator -p 10.0.0.2 -l lan0 -w wan0 -K "$WORK/short.key" 2>&1 \
    | grep -q "too short" && pass "short key refused" || fail "short key accepted"
ip netns exec dev1 "$WORK/tcpveil" -r initiator -p 10.0.0.2 -l lan0 -w wan0 2>&1 \
    | grep -q "Usage" && pass "missing -K refused" || fail "ran without a key"

echo
echo "== $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
