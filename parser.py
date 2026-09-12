import socket
import struct
from dataclasses import dataclass

ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20


@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes


@dataclass
class IPv4Packet:
    src_ip: str
    dst_ip: str
    protocol: int
    payload: bytes


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes


def parse_ethernet(frame: bytes) -> EthernetFrame:
    if len(frame) < 14:
        raise ValueError("frame too short for an Ethernet header")
    dst, src, ethertype = struct.unpack("!6s6sH", frame[:14])
    return EthernetFrame(_format_mac(dst), _format_mac(src), ethertype, frame[14:])


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ipv4(data: bytes) -> IPv4Packet:
    if len(data) < 20:
        raise ValueError("data too short for an IPv4 header")
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        raise ValueError("invalid IPv4 header length")
    protocol = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    return IPv4Packet(src, dst, protocol, data[ihl:])


def parse_tcp(data: bytes) -> TCPSegment:
    if len(data) < 20:
        raise ValueError("data too short for a TCP header")
    src_port, dst_port, seq, ack, offset_byte, flags = struct.unpack("!HHLLBB", data[:14])
    data_offset = (offset_byte >> 4) * 4
    if data_offset < 20 or len(data) < data_offset:
        raise ValueError("invalid TCP data offset")
    return TCPSegment(src_port, dst_port, seq, ack, flags, data[data_offset:])
