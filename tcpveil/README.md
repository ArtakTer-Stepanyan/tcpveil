# TCPVeil

Encrypts TCP/IPv4 traffic between two Linux devices sitting inline between two hosts:

```
PC1 -- Device1 ==== Device2 -- PC2
```

- Device1 and Device2 agree on a session key with Diffie-Hellman (ffdhe2048), authenticated with a pre-shared key.
- The TCP payload is encrypted with AES-256-GCM. IP and TCP headers stay as they are, and an 8-byte counter plus the 16-byte tag are appended. No UDP, no extra header.
- The nonce is a per-direction salt plus the counter, so it is never reused within a session.
- The receiver checks for replays, verifies the tag, decrypts, fixes the IP/TCP checksums and forwards the packet. Anything that fails is dropped.

## Build

```sh
sudo apt install build-essential libssl-dev libnetfilter-queue-dev iptables ethtool
gcc -O2 -Wall -Wextra -D_GNU_SOURCE -o tcpveil src/*.c -lnetfilter_queue -lcrypto -lpthread
```

## Run

Same key file on both devices:

```sh
(umask 077; head -c 32 /dev/urandom | base64 > /etc/tcpveil.key)
```

Device2:

```sh
sudo ./setup-device.sh up eth0 eth1 10.1.0.0/24 10.0.0.1
sudo ./tcpveil -r responder -p 10.0.0.1 -l eth0 -w eth1 -K /etc/tcpveil.key
```

Device1:

```sh
sudo ./setup-device.sh up eth0 eth1 10.2.0.0/24 10.0.0.2
sudo ./tcpveil -r initiator -p 10.0.0.2 -l eth0 -w eth1 -K /etc/tcpveil.key
```

`eth0` faces the host and `eth1` faces the other device.

## Test

Runs the whole chain on one machine using network namespaces:

```sh
sudo ./test-netns.sh
```

## Limitations

IPv4 only, no fragments, no rekeying, and every packet grows by 24 bytes (the setup script clamps the MSS to 1400).
