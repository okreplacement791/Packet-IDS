import struct
from dataclasses import dataclass

MAX_POINTER_JUMPS = 128


@dataclass
class DNSQuestion:
    qname: str
    qtype: int


@dataclass
class DNSMessage:
    id: int
    qdcount: int
    question: DNSQuestion


def read_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumps = 0
    end_offset = None
    while True:
        if offset >= len(msg):
            raise ValueError("DNS name runs past end of message")
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise ValueError("truncated DNS compression pointer")
            if end_offset is None:
                end_offset = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise ValueError("too many DNS compression pointer jumps")
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label length byte")
        offset += 1
        labels.append(msg[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (end_offset if end_offset is not None else offset)


def parse_dns(msg: bytes) -> DNSMessage:
    if len(msg) < 12:
        raise ValueError("data too short for a DNS header")
    id_, _flags, qdcount, _an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if qdcount < 1:
        raise ValueError("DNS message has no question")
    qname, offset = read_name(msg, 12)
    if offset + 4 > len(msg):
        raise ValueError("data too short for DNS question qtype/qclass")
    qtype, _qclass = struct.unpack("!HH", msg[offset:offset + 4])
    return DNSMessage(id_, qdcount, DNSQuestion(qname, qtype))
