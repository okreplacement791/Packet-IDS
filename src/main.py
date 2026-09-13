import argparse
import datetime
import sys

from capture import capture
from engine import load_rules, matches
from parser import ETHERTYPE_IPV4, PROTO_TCP, parse_ethernet, parse_ipv4, parse_tcp

RULES_PATH = "rules.conf"


def run(iface: str | None) -> None:
    rules = load_rules(RULES_PATH)
    for frame in capture(iface):
        eth = parse_ethernet(frame)
        if eth.ethertype != ETHERTYPE_IPV4:
            continue
        try:
            ip = parse_ipv4(eth.payload)
        except ValueError:
            continue
        if ip.protocol != PROTO_TCP:
            continue
        try:
            tcp = parse_tcp(ip.payload)
        except ValueError:
            continue
        for rule in rules:
            if matches(rule, ip, tcp):
                alert(rule.msg, ip.src_ip, tcp.src_port, ip.dst_ip, tcp.dst_port)


def alert(msg: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> None:
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    print(f"[{ts}] ALERT {msg}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="packet-ids")
    parser.add_argument("-i", "--interface", default=None)
    args = parser.parse_args()
    try:
        run(args.interface)
    except PermissionError:
        sys.exit("packet-ids: raw socket capture needs root (try sudo)")
    except KeyboardInterrupt:
        pass
