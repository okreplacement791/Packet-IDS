![Python package](https://github.com/okreplacement791/Packet-IDS/actions/workflows/python-package.yml/badge.svg)

# packet-ids

Passive network intrusion detection. Captures raw Ethernet frames, parses them by hand (no libpcap, no scapy), and flags traffic matching known-bad patterns.

## Why

Every other network tool assumes you're fine trusting a library, a vendor, a black box, to tell you what's actually happening on your own network. libpcap's fine until it isn't. I'd rather know exactly what's being read off the wire and how, byte by byte, than hand that trust to someone else's code I've never looked at.

## How it works

A raw socket (`AF_PACKET`) reads Ethernet frames directly off an interface, no kernel-side filtering, everything that arrives gets processed. Each frame is decoded by hand: the Ethernet header first, then IPv4, then either TCP or (for UDP traffic) a DNS parser that understands compression pointers. Once a packet is fully understood, it's checked against every rule in the loaded ruleset, and any match generates an alert.

## Project structure

    src/
      capture.py   raw socket handling
      parser.py    Ethernet/IPv4/TCP header parsing
      dns.py       DNS message parsing (UDP payloads)
      engine.py    rule parsing and matching
      main.py      wires capture -> parse -> rule match -> alert
    tests/
      test_parser.py
      test_dns.py
      test_engine.py
    rules.conf     the active ruleset

## What it does right now

- Raw packet capture on Linux via `AF_PACKET`. Sees every frame on an interface, no kernel-side filtering yet.
- Parses Ethernet, IPv4, and TCP headers directly from bytes.
- Parses DNS queries over UDP (single question, qname + qtype, including compression-pointer resolution).
- A rule engine reads a Suricata-style ruleset from `rules.conf` and matches packets against it on protocol, IP, port, and TCP flags.
- Rules are filtered by protocol correctly (TCP, UDP) before any other field is checked, so a UDP-only rule won't fire on TCP traffic.
- Alerts print to stdout with a timestamp and the source/destination of the offending packet.

Example output:

    [2026-09-12T14:32:01] ALERT TCP-NULL-SCAN: 10.0.0.5:51223 -> 10.0.0.12:22

## Rules

Rules live in `rules.conf`, one per line, in a simplified Suricata-style syntax:

    alert tcp any any -> any any (msg:"TCP-NULL-SCAN"; flags:0;)

Reading left to right: `alert` is the action, `tcp` is the protocol to match, the first `any any` is the source IP and port (`any` matches anything), `->` separates source from destination, the second `any any` is the destination IP and port, and everything in parentheses is the rule's options. `msg` sets the label an alert prints under. `flags` checks the TCP flags byte exactly, currently only the numeric form (`flags:0;`) is supported, not letter shorthand like `S`/`F`/`A`.

A second rule matching only SSH traffic on port 22 would look like:

    alert tcp any any -> any 22 (msg:"SSH-TRAFFIC";)

Multiple rules can be listed, one per line; every rule is checked against every packet.

## Testing

Each test file builds real packet bytes by hand with `struct.pack`, rather than relying on captured packet fixtures, and asserts the parser or rule engine produces the expected result. No mocking, no external test data.

## What it doesn't do yet

- No IPv6, no IP fragmentation reassembly, no TCP options parsing.
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
