# nids

A minimal network intrusion detection system in C. It reads a `.pcap` file,
parses Ethernet → IPv4 → TCP without copying, and scans every TCP payload
against a rules file in a single pass (Aho-Corasick).

## Usage

```sh
./build/ids [-v] <capture.pcap> [rules]
```

Prints one `ALERT` line per matching rule per packet, then a summary. Rules
default to `rules/default.rules`; `-v` also prints every TCP packet with a
payload preview.

```
$ ./build/ids samples/test.pcap
ALERT pkt=6 sid=1001 msg="Test signature (samples/test.pcap)" 10.0.0.5:49152 -> 93.184.216.34:80 offset=0

---
6 packets, 5 IPv4, 4 TCP, 1 alerts
```

## Build

Linux, or WSL with Ubuntu on Windows.

```sh
sudo apt-get install build-essential libpcap-dev
make
make test    # samples/test.pcap against samples/test.rules
```

## Rules

One per line: `<sid> "<message>" <content>`. Content is matched byte-for-byte
(case-sensitive) anywhere in a TCP payload; binary bytes go in Snort-style
`|hex|` blocks.

```
1004  "XSS cookie theft"   <script>alert(document.cookie)
1008  "x86 NOP sled"       |90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90|
```

## Benchmarks

Synthetic labelled traffic with a fixed seed, run on Ubuntu (WSL2), single
thread, `-O2`.

| Test | Result |
|---|---|
| Detection: attack in one plain TCP packet | **100%** (320/320) |
| Detection: attack via VLAN, IPv6, UDP, split fragments or split segments | 0% (0/800) |
| False positives: normal web traffic | **0.00%** (0/10,000) |
| False positives: web pages quoting attack strings | 71.4% (500/700) |
| Alerts match a reference implementation | **100%** (18,140 packets) |
| Payload extraction: well-formed packets | **100%** (2,000/2,000) |
| Malformed packets rejected | **100%** (1,200/1,200) |
| ASan / UBSan / LSan reports over 220,000 fuzzed packets | **0** |
| Throughput with 8 / 1,000 / 5,000 rules | 2.26M / 1.26M / 0.58M packets/s |

## Limits

- Offline only: reads `.pcap` files, no live capture.
- Ethernet + IPv4 + TCP only; VLAN, IPv6 and UDP are skipped.
- No stream reassembly, so a signature split across packets is missed.
- Content rules can't see inside HTTPS, and they fire on pages that merely
  quote an attack string.
- Literal, case-sensitive matching: encodings like `%2e%2e/` get past it.
- No port-scan or flood detection.
