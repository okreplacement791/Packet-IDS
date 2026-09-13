from parser import TCPSegment

RULE_NAME = "TCP-NULL-SCAN"


def null_scan_rule(tcp: TCPSegment) -> bool:
    return tcp.flags == 0
