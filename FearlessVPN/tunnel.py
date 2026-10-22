#!/usr/bin/env python3
"""
Stage 1 toy VPN: bridges a TUN device to a UDP socket.

NO ENCRYPTION, NO AUTHENTICATION. This is for learning how packets flow,
on a lab network or two namespaces. Never carry real traffic with it.

Usage (needs root, Linux only):
  sudo python3 tunnel.py --tun tun0 --listen 5000 --peer 203.0.113.5:5000

The side without --peer learns the peer address from the first packet
it receives (fine for stage 1, insecure by design).
"""
import argparse
import fcntl
import os
import select
import socket
import struct

TUNSETIFF = 0x400454CA   # ioctl to configure a tun/tap device
IFF_TUN = 0x0001         # layer 3 (raw IP packets); IFF_TAP would be layer 2
IFF_NO_PI = 0x1000       # no extra 4-byte packet-info header

BUF = 65535


def open_tun(name: str) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def main() -> None:
    ap = argparse.ArgumentParser(description="Toy TUN<->UDP tunnel (no crypto)")
    ap.add_argument("--tun", default="tun0", help="TUN interface name")
    ap.add_argument("--listen", type=int, required=True, help="local UDP port")
    ap.add_argument("--peer", help="remote host:port (omit to learn it)")
    args = ap.parse_args()

    tun = open_tun(args.tun)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.listen))

    peer = None
    if args.peer:
        host, port = args.peer.rsplit(":", 1)
        peer = (host, int(port))

    print(f"[*] {args.tun} <-> udp/{args.listen}, peer={peer}")

    while True:
        readable, _, _ = select.select([tun, sock], [], [])

        if tun in readable:
            # A raw IP packet the kernel wants to send through the tunnel.
            pkt = os.read(tun, BUF)
            if peer:
                sock.sendto(pkt, peer)
            # TODO stage 2: encrypt + authenticate pkt before sendto()

        if sock in readable:
            data, addr = sock.recvfrom(BUF)
            peer = addr  # INSECURE: anyone can hijack the peer address
            # TODO stage 2: verify + decrypt data before writing
            os.write(tun, data)  # inject the packet into the network stack


if __name__ == "__main__":
    main()
