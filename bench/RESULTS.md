# nids benchmark results (Phase 2)

## 1. Detection (signature rules, `rules/default.rules` content)

18,140 packets: 10,700 benign, 1,120 payload attacks (7 delivery variants x 8 signatures x 20), plus a port scan and a SYN flood.
Alerts raised: 820

| Traffic | Events | Alerted | Rate |
|---|---|---|---|
| attack: plain | 160 | 160 | TPR 100.0% |
| attack: ip+tcp options | 160 | 160 | TPR 100.0% |
| attack: 802.1Q VLAN | 160 | 0 | TPR 0.0% |
| attack: IPv6 | 160 | 0 | TPR 0.0% |
| attack: UDP | 160 | 0 | TPR 0.0% |
| attack: IP fragmented | 160 | 0 | TPR 0.0% |
| attack: TCP segmented | 160 | 0 | TPR 0.0% |
| benign: normal web traffic | 10,000 | 0 | FPR 0.00% |
| benign: pages quoting attack strings | 700 | 500 | FPR 71.43% |
| port scan (1000 SYNs) | 1 | 0 | not a content attack (no payload) |
| SYN flood (5000 SYNs) | 1 | 0 | not a content attack (no payload) |

- **TPR, plain delivery** (no evasion): 320/320 = **100.0%**
- **TPR, all 7 delivery variants**: 320/1120 = **28.6%**
- FPR is reported per benign class only: a blended FPR or precision would just reflect the class mix chosen here.

## 2. Matcher correctness (vs Python reference: same sids, same offsets)

- Detection set (8 rules): 18,140/18,140 packets agree = **100.0%**
- Overlap stress set (301 rules of 1-6 bytes over "abc", 618,124 alerts): 3,000/3,000 packets agree = **100.0%**

## 3. Parser accuracy (exact payload extraction vs ground truth)

200 randomized packets per case, 3,800 total.

| Group | Case | Expected | Correct |
|---|---|---|---|
| well-formed | plain TCP | extract payload | 200/200 (100.0%) |
| well-formed | IP options (IHL 6-15) | extract payload | 200/200 (100.0%) |
| well-formed | TCP options (doff 6-15) | extract payload | 200/200 (100.0%) |
| well-formed | IP + TCP options | extract payload | 200/200 (100.0%) |
| well-formed | Ethernet padding (60B SYN) | extract 0 bytes, ignore padding | 200/200 (100.0%) |
| well-formed | snaplen-truncated payload | extract captured bytes | 200/200 (100.0%) |
| well-formed | total_len > captured | clamp to caplen | 200/200 (100.0%) |
| well-formed | first IP fragment (MF) | extract partial payload | 200/200 (100.0%) |
| well-formed | UDP | skip | 200/200 (100.0%) |
| well-formed | ARP | skip | 200/200 (100.0%) |
| malformed | truncated inside TCP header | reject | 200/200 (100.0%) |
| malformed | IHL < 5 | reject | 200/200 (100.0%) |
| malformed | TCP data offset < 5 | reject | 200/200 (100.0%) |
| malformed | total_len < headers | reject | 200/200 (100.0%) |
| malformed | IP version != 4 | reject | 200/200 (100.0%) |
| malformed | non-first IP fragment | don't parse as TCP header | 200/200 (100.0%) |
| coverage | 802.1Q VLAN TCP | extract payload | 0/200 (0.0%) |
| coverage | IPv6 TCP | extract payload | 0/200 (0.0%) |
| coverage | TSO (total_len = 0) | extract captured payload | 0/200 (0.0%) |

- **well-formed**: 2,000/2,000 = **100.0%**
- **malformed**: 1,200/1,200 = **100.0%**
- **coverage**: 0/600 = **0.0%**

## 4. Robustness (ASan + UBSan + LeakSanitizer build)

- Malformed packets fed: 220,000 (200,000 mutated + 20,000 random), all scanned against the rules
- Packets processed: 220,000
- Exit code: 0; memory-safety / UB / leak reports: **0**
- Malformed rule files rejected cleanly (exit 1, error message, no sanitizer report): **12/12**

## 5. Throughput (-O2, alerts only, stdout -> /dev/null, warm cache, median of 5)

1,000,000 packets / 252 MB of benign traffic. Random rules are 8-16 printable bytes.
Startup = loading rules + building the automaton (timed on an empty capture); scan = total - startup.

| Rules | Startup | Total | Scan-only packets/s | Scan-only Gbit/s |
|---|---|---|---|---|
| 0 | 4 ms | 0.405s | 2.49 M | 5.03 |
| 8 (default set) | 4 ms | 0.406s | 2.49 M | 5.02 |
| 100 | 4 ms | 0.502s | 2.01 M | 4.05 |
| 1,000 | 13 ms | 0.675s | 1.51 M | 3.04 |
| 5,000 | 57 ms | 1.398s | 0.75 M | 1.50 |
