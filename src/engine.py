from __future__ import annotations
import re
from dataclasses import dataclass

from parser import IPv4Packet, PROTO_TCP, PROTO_UDP, TCPSegment

_PROTO_NUMS = {"tcp": PROTO_TCP, "udp": PROTO_UDP}

_RULE_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+->\s+"
    r"(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<options>.*)\)\s*$"
)


@dataclass
class Rule:
    action: str
    proto: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    msg: str
    flags: int | None


def parse_rule(line: str) -> Rule:
    m = _RULE_RE.match(line.strip())
    if not m:
        raise ValueError(f"malformed rule: {line!r}")
    options = {}
    for part in m["options"].split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition(":")
        options[key.strip()] = value.strip().strip('"')
    flags = int(options["flags"], 0) if "flags" in options else None
    return Rule(
        action=m["action"],
        proto=m["proto"].lower(),
        src_ip=m["src_ip"],
        src_port=m["src_port"],
        dst_ip=m["dst_ip"],
        dst_port=m["dst_port"],
        msg=options.get("msg", ""),
        flags=flags,
    )


def load_rules(path: str) -> list[Rule]:
    rules = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rules.append(parse_rule(line))
    return rules


def _matches_field(pattern: str, value: str) -> bool:
    return pattern == "any" or pattern == value


def matches(rule: Rule, ip: IPv4Packet, tcp: TCPSegment) -> bool:
    if _PROTO_NUMS.get(rule.proto) != ip.protocol:
        return False
    if not _matches_field(rule.src_ip, ip.src_ip):
        return False
    if not _matches_field(rule.dst_ip, ip.dst_ip):
        return False
    if not _matches_field(rule.src_port, str(tcp.src_port)):
        return False
    if not _matches_field(rule.dst_port, str(tcp.dst_port)):
        return False
    if rule.flags is not None and tcp.flags != rule.flags:
        return False
    return True
