![Python package](https://github.com/okreplacement791/Packet-IDS/actions/workflows/python-package.yml/badge.svg)

# packet-ids

Passive network intrusion detection. Captures raw Ethernet frames, parses them by hand (no libpcap, no scapy), and flags traffic matching known-bad patterns.

## How it works

A raw socket reads Ethernet frames directly off an interface. Each frame gets decoded by hand, Ethernet header, then IPv4, then TCP or UDP/DNS, with no parsing library doing the work. Once a packet is understood, it's checked against the loaded ruleset.

## What it does right now

- Raw packet capture on Linux via `AF_PACKET`. Sees every frame on an interface, no kernel-side filtering yet.
- Parses Ethernet, IPv4, and TCP headers directly from bytes.
- Parses DNS queries over UDP (single question, qname + qtype, including compression-pointer resolution).
- A rule engine reads a Suricata-style ruleset from `rules.conf` and matches packets against it on protocol, IP, port, and TCP flags.
- Alerts print to stdout with a timestamp and the source/destination of the offending packet.

Example output:

    [2026-09-12T14:32:01] ALERT TCP-NULL-SCAN: 10.0.0.5:51223 -> 10.0.0.12:22

## Rules

Rules live in `rules.conf`, one per line:

    alert tcp any any -> any any (msg:"TCP-NULL-SCAN"; flags:0;)

`any` matches anything for that field. `flags` currently only accepts the numeric form (`flags:0;`), not the letter shorthand (`S`, `F`, `A`, etc.) some other tools use.

## What it doesn't do yet

- No IPv6, no IP fragmentation reassembly, no TCP options parsing.
- Rule matching only checks protocol when a rule explicitly targets TCP; non-TCP rules aren't filtered by protocol yet.
- No persistent logging. Alerts go to stdout only, nothing is saved to disk.
- Single-question DNS parsing only; multi-question messages and most non-A/AAAA record types aren't handled.

## Requirements

- Linux only. Capture uses `AF_PACKET`, which doesn't exist on macOS or Windows.
- Python 3.9+.
- Root privileges to open a raw socket. No other dependencies.

## Running it

Needs root, since raw packet capture requires it:

    sudo python3 src/main.py -i <interface>

Leave `-i` off to listen on all interfaces. Run the self-tests with:

    python3 tests/test_parser.py
    python3 tests/test_dns.py
    python3 tests/test_engine.py

---
