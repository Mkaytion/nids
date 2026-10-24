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

All numbers come from the scripts in [`bench/`](bench/). Run on Ubuntu (WSL2),
single thread, `-O2`; speeds vary by machine.

```sh
make bench         # synthetic suite      -> bench/RESULTS.md
make bench-real    # real traffic, ~1.8 GB download -> bench/CIC-IDS2018.md
```

### Implementation checks

Synthetic packets with known answers ([full results](bench/RESULTS.md)).

| Test | Result |
|---|---|
| Alerts match a reference implementation | **100%** (18,140 packets) |
| Payload extraction: well-formed packets | **100%** (2,000/2,000) |
| Malformed packets rejected | **100%** (1,200/1,200) |
| ASan / UBSan / LSan reports over 220,000 fuzzed packets | **0** |
| Throughput with 8 / 1,000 / 5,000 rules | 2.49M / 1.51M / 0.75M packets/s |

### Real traffic: CSE-CIC-IDS2018

19 captures from Thursday 22 Feb 2018 of the public
[CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) dataset
(3.0M packets, 1.8 GB), labelled from the dataset's published attacker and
victim addresses ([full results](bench/CIC-IDS2018.md)). The default rules were
committed before the dataset was examined and were not changed for it.

| Traffic (TCP connections with payload) | Alerted |
|---|---|
| Attacks: XSS, SQL injection, login brute force | 0% (0/202) |
| Benign | 0.000% (0/74,117) |

Nothing was detected because the real attacks don't contain the default rules'
literal strings: the payloads are URL-encoded (`%3Cscript%3E`) and use other
forms (`console.log(...)`, `' and 1=1`). 66% of TCP payload bytes were also
encrypted.

### Detection on synthetic traffic

These rows test the matcher, not real-world detection: the attacks were written
to contain the rule strings, and the benign traffic was generated.

| Test | Result |
|---|---|
| Attack in one plain TCP packet | 100% (320/320) |
| Attack via VLAN, IPv6, UDP, split fragments or split segments | 0% (0/800) |
| False positives: generated web traffic | 0.00% (0/10,000) |
| False positives: generated pages quoting attack strings | 71.4% (500/700) |

## Limits

- Offline only: reads `.pcap` files, no live capture.
- Ethernet + IPv4 + TCP only; VLAN, IPv6 and UDP are skipped.
- No stream reassembly, so a signature split across packets is missed.
- Content rules can't see inside HTTPS, and they fire on pages that merely
  quote an attack string.
- Literal, case-sensitive matching with no HTTP decoding: URL-encoded payloads
  get past it, which is why it missed every real attack above.
- No port-scan or flood detection.
