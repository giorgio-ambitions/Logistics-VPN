import argparse
import fcntl
import os
import select
import socket
import struct

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
BUF = 65535

def open_tun(name: str) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd

def main() -> None:
    ap = argparse.ArgumentParser(description="Circles: A ring-topology TUN/UDP router")
    ap.add_argument("--tun", default="tun0", help="TUN interface name")
    ap.add_argument("--listen", type=int, required=True, help="local UDP port to receive from previous hop")
    ap.add_argument("--next-hop", required=True, help="next node host:port in the circle (e.g., 127.0.0.1:5001)")
    args = ap.parse_args()

    tun = open_tun(args.tun)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.listen))

    next_host, next_port = args.next_hop.rsplit(":", 1)
    next_peer = (next_host, int(next_port))

    print(f"[*] Circle Node Active: TUN '{args.tun}' -> Listening on UDP/{args.listen} -> Forwarding to {next_peer}")

    while True:
        readable, _, _ = select.select([tun, sock], [], [])

        if tun in readable:
            # Local OS wants to send a packet out
            pkt = os.read(tun, BUF)
            # Forward it along the circle
            sock.sendto(pkt, next_peer)

        if sock in readable:
            # Packet received from the previous node in the circle
            data, addr = sock.recvfrom(BUF)
            
            # TODO: Inspect packet destination. 
            # If it's meant for this node, inject into TUN. 
            # If it's meant for someone else further down the circle, forward to next_peer!
            os.write(tun, data)

if __name__ == "__main__":
    main()
