import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import socket
import struct

from parser import ETHERTYPE_IPV4, PROTO_TCP, parse_ethernet, parse_ipv4, parse_tcp


def build_frame(tcp_flags: int) -> bytes:
    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x11" * 6, ETHERTYPE_IPV4)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 0, 0, 64, PROTO_TCP, 0,
        socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"),
    )
    tcp = struct.pack("!HHLLBBHHH", 12345, 80, 0, 0, 0x50, tcp_flags, 0, 0, 0)
    return eth + ip + tcp


def test_parses_null_scan_packet():
    eth = parse_ethernet(build_frame(tcp_flags=0))
    assert eth.ethertype == ETHERTYPE_IPV4
    ip = parse_ipv4(eth.payload)
    assert (ip.src_ip, ip.dst_ip, ip.protocol) == ("127.0.0.1", "127.0.0.1", PROTO_TCP)
    tcp = parse_tcp(ip.payload)
    assert (tcp.src_port, tcp.dst_port, tcp.flags) == (12345, 80, 0)


if __name__ == "__main__":
    test_parses_null_scan_packet()
    print("ok")
