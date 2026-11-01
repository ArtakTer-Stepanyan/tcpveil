#!/bin/sh
set -eu

if [ $# -lt 5 ]; then
    echo "usage: $0 up|down LAN_IF WAN_IF REMOTE_SUBNET PEER_WAN_IP [QUEUE]" >&2
    echo "example: $0 up eth0 eth1 10.2.0.0/24 10.0.0.2" >&2
    exit 1
fi

MODE=$1 LAN=$2 WAN=$3 REMOTE=$4 PEER=$5 QUEUE=${6:-0}

# MSS clamp only on LAN->WAN: changing a protected SYN on the WAN side would break its tag.
RULES="mangle|FORWARD|-i $LAN -o $WAN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
filter|FORWARD|-i $LAN -o $WAN -p tcp -j NFQUEUE --queue-num $QUEUE
filter|FORWARD|-i $WAN -o $LAN -p tcp -j NFQUEUE --queue-num $QUEUE"

rules() {
    echo "$RULES" | while IFS='|' read -r table chain rule; do
        if iptables -t "$table" -C "$chain" $rule 2>/dev/null; then
            [ "$1" = del ] && iptables -t "$table" -D "$chain" $rule
        else
            [ "$1" = add ] && iptables -t "$table" -A "$chain" $rule
        fi
        true
    done
}

case $MODE in
up)
    sysctl -qw net.ipv4.ip_forward=1
    for dev in "$LAN" "$WAN"; do
        ethtool -K "$dev" gro off gso off tso off lro off 2>/dev/null || true
    done
    rules add
    ip route replace "$REMOTE" via "$PEER" dev "$WAN"
    echo "tcpveil device setup done: lan=$LAN wan=$WAN remote=$REMOTE via $PEER queue=$QUEUE"
    ;;
down)
    rules del
    ip route del "$REMOTE" via "$PEER" dev "$WAN" 2>/dev/null || true
    echo "tcpveil device setup removed"
    ;;
*)
    echo "unknown mode '$MODE' (use up or down)" >&2
    exit 1
    ;;
esac
