# nids

A minimal **Network Intrusion Detection System** written in C, built to learn
high-performance systems programming: raw packet capture with `libpcap` and
**zero-copy** protocol parsing.

> ⚠️ **Educational project.** It runs in **offline mode** — reading packets from
> a saved `.pcap` file rather than a live interface. That's how security
> engineers actually test an IDS: the same traffic can be replayed repeatedly
> while debugging, so results are perfectly reproducible.

## What it does

Given a capture file, `nids` walks every packet down the header stack —
**Ethernet → IPv4 → TCP** — and extracts a pointer to the **application
payload**: the raw bytes an attacker's data actually lives in. It does this
without copying a single byte, and correctly even when the headers vary in
length.

```
$ ./build/ids samples/test.pcap
[2] TCP  10.0.0.5 -> 93.184.216.34  (ip_hdr_len=20, caplen=54)
      payload: 0 bytes  ""
[3] TCP  10.0.0.5 -> 93.184.216.34  (ip_hdr_len=20, caplen=101)
      payload: 47 bytes  "GET /index.html HTTP/1.1..Host: example."
[4] TCP  93.184.216.34 -> 10.0.0.5  (ip_hdr_len=20, caplen=108)
      payload: 54 bytes  "HTTP/1.1 200 OK..Content-Length: 15....<"
[6] TCP  10.0.0.5 -> 93.184.216.34  (ip_hdr_len=24, caplen=95)
      payload: 25 bytes  "EVIL_PAYLOAD_SIGNATURE_v1"

---
6 packets, 5 IPv4, 4 TCP
```

## Roadmap

- **Phase 1 — Zero-copy protocol parser** ✅ *(complete)*: overlay packed
  structs on the raw byte buffer to walk Ethernet → IPv4 → TCP and locate the
  payload.
- **Phase 2 — Signature matching**: scan each extracted payload for known-bad
  byte patterns and raise alerts.
- *(later)* live capture, more protocols, stateful stream reassembly.

## Build (Linux / WSL)

`libpcap` is native on Linux. On Windows, build inside **WSL with a real distro**
(the `docker-desktop` WSL distro has no `apt`):

```sh
# one-time: install Ubuntu if you don't have it
wsl --install -d Ubuntu

# inside Ubuntu:
sudo apt-get update
sudo apt-get install build-essential libpcap-dev

# from the project directory:
make
```

> The Makefile uses `-std=gnu11`, not `-std=c11`, on purpose: libpcap's headers
> use BSD type names (`u_char`, `u_int`, …) that glibc hides in strict-ISO mode.

## Run

```sh
./build/ids <capture.pcap>
make run PCAP=samples/test.pcap      # build + run in one step
```

A ready-made test capture ships in [`samples/test.pcap`](samples/test.pcap)
(described [below](#the-test-capture)). To make your own:

```sh
sudo tcpdump -i any -c 200 -w mine.pcap
./build/ids mine.pcap
```

## How the parser works

### Zero-copy overlay

A captured packet is just a flat `uint8_t` array. Rather than copying fields out
one at a time, `nids` lays a packed `struct` pointer directly over the buffer, so
`ip->protocol` reads straight from the wire. Each header is found by advancing a
**byte pointer** to the right offset and casting:

```
 offset 0            14                    14+ihl               14+ihl+tcphl
 |                   |                     |                    |
 +-------------------+---------------------+--------------------+--------------+
 | Ethernet header   | IPv4 header         | TCP header         | payload ...  |
 | 14 bytes (fixed)  | ihl * 4  (≥20, var) | dataoff*4 (≥20,var)|              |
 +-------------------+---------------------+--------------------+--------------+
 ^ packet            ^ packet + 14         ^ ip + ip_hdr_len    ^ tcp + tcp_hdr_len
   = eth                = ip                  = tcp                = payload
```

The one subtlety that makes or breaks this: **C pointer arithmetic scales by the
pointed-to type**. `ip + ip_hdr_len` would advance `ip_hdr_len × sizeof(ipv4_hdr)`
bytes — completely wrong. Casting to a byte pointer first makes `+ n` mean
"advance exactly `n` bytes":

```c
const struct tcp_hdr *tcp =
    (const struct tcp_hdr *)((const uint8_t *)ip + ip_hdr_len);
```

Two rules keep the overlay aligned with the wire format:

1. **Packed structs** — `__attribute__((packed))` removes the padding the
   compiler would otherwise insert between fields.
2. **Byte order** — multi-byte fields are big-endian on the wire, so they're read
   through `ntohs()` / `ntohl()` before being used as numbers.

See [`include/net_structs.h`](include/net_structs.h) for the header layouts.

### Variable-length headers (the part that bites people)

Both the IPv4 and TCP headers can be *longer* than their 20-byte minimum when
they carry options — so their lengths must be **computed, never assumed**:

- **IPv4** — the low nibble of the first byte (IHL) counts 32-bit words, so
  `ip_hdr_len = IHL * 4` (20 with no options).
- **TCP** — the high nibble of byte 12 (data offset) also counts 32-bit words,
  so `tcp_hdr_len = data_offset * 4` (20 with no options).

Any parser that hardcodes `20 + 20` breaks the moment options appear. Packet #6
in the sample is built specifically to catch that bug: it has a 24-byte IP header
*and* a 32-byte TCP header, so its payload starts at byte **70**, not 54. The
fact that it decodes cleanly to `EVIL_PAYLOAD_SIGNATURE_v1` is the proof the math
is right.

### Bounds checking (parsing hostile input)

An IDS parses attacker-controlled data, so every offset is validated against
`header->caplen` (the number of bytes actually captured) *before* dereferencing:

- The TCP header is checked in two stages — first the fixed 20 bytes (enough to
  read the data-offset field), then the full option-inclusive length once it's
  known.
- The payload length is derived from the IP header's `total_len` and computed in
  **signed** arithmetic, so a malformed packet whose headers exceed `total_len`
  produces a negative value that's rejected — rather than an unsigned underflow
  to ~4 billion that would send the scanner reading off the end of the buffer.
- The result is finally **clamped to `caplen`**, so a truncated capture can never
  cause an over-read.

That discipline is the difference between an IDS and a segfault generator.

## The test capture

[`samples/test.pcap`](samples/test.pcap) is a tiny, hand-built Ethernet capture
that exercises every branch of the parser. Expected output is the oracle you can
check a build against:

| # | Packet | Parser action | Payload |
|---|--------|---------------|---------|
| 1 | ARP | skipped — not IPv4 | — |
| 2 | TCP SYN | parsed | 0 bytes |
| 3 | HTTP GET | parsed | 47 bytes |
| 4 | HTTP 200 response | parsed | 54 bytes |
| 5 | UDP | skipped — not TCP | — |
| 6 | TCP **+ IP & TCP options** | parsed | 25 bytes at offset **70** |

**Expected summary: `6 packets, 5 IPv4, 4 TCP`** — read it as a funnel: 6
arrived, 1 (ARP) dropped at Layer 2 → 5 IPv4, 1 (UDP) dropped at Layer 3 → 4 TCP
reached payload extraction. (`EVIL_PAYLOAD_SIGNATURE_v1` is a benign placeholder,
deliberately *not* the real EICAR string, so it won't trip antivirus.)

## Project layout

```
include/net_structs.h   packed Ethernet / IPv4 / TCP header structs
src/ids.c               pcap setup, per-packet callback, header walk
samples/test.pcap       hand-built capture for testing (see above)
Makefile                build (+ `make run`)
```
