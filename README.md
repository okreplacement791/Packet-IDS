# packet-ids

Passive network intrusion detection. Captures raw Ethernet frames, parses them by hand (no libpcap, no scapy), and flags traffic matching known-bad patterns.

## What it does right now

- Raw packet capture on Linux via `AF_PACKET`. Sees every frame on an interface, no kernel-side filtering yet.
- Parses Ethernet, IPv4, and TCP headers directly from bytes.
- Parses DNS queries over UDP (single question, qname + qtype, including compression-pointer resolution).
- One rule: flags TCP segments with no flags set at all, the classic `nmap -sN` null-scan probe.
- Alerts print to stdout with a timestamp and the source/destination of the offending packet.

## What it doesn't do yet

- No IPv6, no IP fragmentation reassembly, no TCP options parsing.
- No rule engine. The null-scan check is the only detection logic, hardcoded.
- No persistent logging. Alerts go to stdout only, nothing is saved to disk.
- Single-question DNS parsing only; multi-question messages and most non-A/AAAA record types aren't handled.

## Running it

Needs root, since raw packet capture requires it:

```
sudo python3 main.py -i <interface>
```

Leave `-i` off to listen on all interfaces. Run the self-tests with:

```
python3 test_parser.py
python3 test_dns.py
```
