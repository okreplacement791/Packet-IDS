import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import struct

from dns import parse_dns, read_name


def encode_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += struct.pack("B", len(label)) + label.encode("ascii")
    return out + b"\x00"


def build_query(qname: str, qtype: int = 1, qclass: int = 1, id_: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", id_, 0x0100, 1, 0, 0, 0)
    question = encode_qname(qname) + struct.pack("!HH", qtype, qclass)
    return header + question


def test_parses_simple_query():
    msg = build_query("example.com", qtype=1)
    parsed = parse_dns(msg)
    assert parsed.id == 0x1234
    assert parsed.question.qname == "example.com"
    assert parsed.question.qtype == 1


def test_resolves_compression_pointer():
    header = struct.pack("!HHHHHH", 0x0001, 0x8180, 1, 1, 0, 0)
    name_offset = len(header)
    name_bytes = encode_qname("example.com")
    question = name_bytes + struct.pack("!HH", 1, 1)
    pointer_offset = len(header) + len(question)
    pointer = struct.pack("!H", 0xC000 | name_offset)
    answer = pointer + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
    msg = header + question + answer

    resolved, next_offset = read_name(msg, pointer_offset)
    assert resolved == "example.com"
    assert next_offset == pointer_offset + 2


def test_rejects_pointer_loop():
    msg = struct.pack("!H", 0xC000) + b"\x00"
    try:
        read_name(msg, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected a pointer loop to raise ValueError")


if __name__ == "__main__":
    test_parses_simple_query()
    test_resolves_compression_pointer()
    test_rejects_pointer_loop()
    print("ok")
