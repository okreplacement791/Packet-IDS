import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from engine import load_rules, matches, parse_rule
from parser import PROTO_TCP, IPv4Packet, TCPSegment

NULL_SCAN_LINE = 'alert tcp any any -> any any (msg:"TCP-NULL-SCAN"; flags:0;)'


def test_parses_rule_fields():
    rule = parse_rule(NULL_SCAN_LINE)
    assert (rule.action, rule.proto) == ("alert", "tcp")
    assert (rule.src_ip, rule.src_port, rule.dst_ip, rule.dst_port) == ("any", "any", "any", "any")
    assert rule.msg == "TCP-NULL-SCAN"
    assert rule.flags == 0


def test_matches_null_scan_packet():
    rule = parse_rule(NULL_SCAN_LINE)
    ip = IPv4Packet("10.0.0.1", "10.0.0.2", PROTO_TCP, b"")
    tcp = TCPSegment(12345, 80, 0, 0, 0, b"")
    assert matches(rule, ip, tcp) is True


def test_does_not_match_syn_packet():
    rule = parse_rule(NULL_SCAN_LINE)
    ip = IPv4Packet("10.0.0.1", "10.0.0.2", PROTO_TCP, b"")
    tcp = TCPSegment(12345, 80, 0, 0, 0x02, b"")
    assert matches(rule, ip, tcp) is False


def test_matches_specific_port_only():
    rule = parse_rule('alert tcp any any -> any 22 (msg:"SSH-HIT"; flags:0;)')
    ip = IPv4Packet("10.0.0.1", "10.0.0.2", PROTO_TCP, b"")
    hit = TCPSegment(12345, 22, 0, 0, 0, b"")
    miss = TCPSegment(12345, 80, 0, 0, 0, b"")
    assert matches(rule, ip, hit) is True
    assert matches(rule, ip, miss) is False


def test_load_rules_skips_blank_lines_and_comments():
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write("# comment\n\n" + NULL_SCAN_LINE + "\n")
        path = f.name
    try:
        rules = load_rules(path)
        assert len(rules) == 1
        assert rules[0].msg == "TCP-NULL-SCAN"
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_parses_rule_fields()
    test_matches_null_scan_packet()
    test_does_not_match_syn_packet()
    test_matches_specific_port_only()
    test_load_rules_skips_blank_lines_and_comments()
    print("ok")
