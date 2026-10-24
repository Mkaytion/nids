# nids on real traffic: CSE-CIC-IDS2018

Thursday 22 Feb 2018, 19 captures (the attacked web server + 18 other hosts), 3,048,705 packets, 1.78 GB. Rules: `default.rules` unchanged.

## Detection (per TCP connection with payload)

| Traffic | Connections | Alerted | Rate |
|---|---|---|---|
| attack: XSS | 41 | 0 | TPR 0.0% |
| attack: SQL injection | 16 | 0 | TPR 0.0% |
| attack: login brute force | 137 | 0 | TPR 0.0% |
| attack: attacker page loads | 8 | 0 | TPR 0.0% |
| benign | 74,117 | 0 | FPR 0.000% |

## What nids could see

| Packets | Share |
|---|---|
| IPv4 TCP (inspected) | 91.6% |
| IPv4 UDP | 4.9% |
| ARP | 3.1% |
| IPv6 | 0.3% |
| IPv4 ICMP | 0.2% |
| IPv4 other | 0.0% |

66.0% of TCP payload bytes are on encrypted ports (443, 22, 3389, 993, 995, 465, 636), where content rules only see ciphertext.

Throughput on this traffic: 0.87 M packets/s (4.06 Gbit/s), process start-up included.
