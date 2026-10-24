#!/usr/bin/env python3
"""Evaluate nids on real traffic: CSE-CIC-IDS2018, Thursday 22 Feb 2018 (web attacks on DVWA).

usage: cicids2018.py fetch <datadir>                 # ~1.8 GB, cut out of the 50 GB day zip with HTTP range requests
       cicids2018.py eval <ids> <rules> <datadir>    # writes bench/CIC-IDS2018.md

Labels follow the dataset's published attack table: every TCP connection between the attacker
18.218.115.60 and the web server 172.31.69.28 is an attack; all other traffic is benign. Attack
connections are typed by the requests they carry (XSS, SQL injection, login brute force).
"""
import collections, io, os, re, shutil, struct, subprocess, sys, time, urllib.request, zipfile

ZIP = ('https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'
       'Original%20Network%20Traffic%20and%20Log%20data/Thursday-22-02-2018/pcap.zip')
VICTIM_FILE, VICTIM, ATTACKER = 'pcap/UCAP172.31.69.28', '172.31.69.28', '18.218.115.60'


class HttpFile(io.RawIOBase):
    """Seekable read-only view of a URL, so zipfile can pull single members out of a huge archive."""
    def __init__(self, url):
        self.url, self.pos = url, 0
        self.size = int(urllib.request.urlopen(urllib.request.Request(url, method='HEAD')).headers['Content-Length'])
    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos
    def seek(self, off, whence=0):
        self.pos = (off, self.pos + off, self.size + off)[whence]
        return self.pos
    def readinto(self, b):
        if self.pos >= self.size: return 0
        rng = f'bytes={self.pos}-{min(self.pos + len(b), self.size) - 1}'
        data = urllib.request.urlopen(urllib.request.Request(self.url, headers={'Range': rng})).read()
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def pick(infos):
    """The web server, every other Ubuntu server, and the 3 median-sized captures of each Windows/EC2 host type."""
    names = [VICTIM_FILE] + sorted(i.filename for i in infos if i.filename.startswith('pcap/UCAP') and i.filename != VICTIM_FILE)
    for kind in ('capDESKTOP', 'capPC1', 'capWIN', 'capEC2AMAZ'):
        group = sorted((i.file_size, i.filename) for i in infos if i.filename.startswith('pcap/' + kind))
        med = group[len(group) // 2][0]
        names += [n for _, n in sorted(group, key=lambda g: (abs(g[0] - med), g[1]))[:3]]
    return names


def fetch(datadir):
    os.makedirs(datadir, exist_ok=True)
    z = zipfile.ZipFile(io.BufferedReader(HttpFile(ZIP), 16 << 20))
    for name in pick(z.infolist()):
        out = os.path.join(datadir, name.split('/')[-1] + '.pcap')
        if os.path.exists(out):
            continue
        print('fetching', name, flush=True)
        with z.open(name) as src, open(out + '.part', 'wb') as dst:
            shutil.copyfileobj(src, dst, 1 << 22)
        os.rename(out + '.part', out)


def packets(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\xd4\xc3\xb2\xa1', 'expected a little-endian microsecond pcap'
    o, i = 24, 0
    while o + 16 <= len(d):
        cl = struct.unpack_from('<I', d, o + 8)[0]
        if o + 16 + cl > len(d):
            break                       # truncated last record
        i += 1
        yield i, d[o + 16:o + 16 + cl]
        o += 16 + cl


def ip(b): return '.'.join(map(str, b))

ALERT = re.compile(r'^ALERT pkt=(\d+) sid=(\d+) ')
SUMMARY = re.compile(r'^(\d+) packets, \d+ IPv4, \d+ TCP, (\d+) alerts$')
KINDS = [('XSS', b'/vulnerabilities/xss_r/?'), ('SQL injection', b'/vulnerabilities/sqli/?'),
         ('login brute force', b'POST /DVWA/login.php')]
RANK = {kind: r for r, (kind, _) in enumerate(KINDS)}


def evaluate(ids, rules, datadir):
    files = sorted(f for f in os.listdir(datadir) if f.endswith('.pcap'))
    mix = collections.Counter()           # packets by what nids can see
    tcp_bytes = collections.Counter()     # TCP payload bytes by service port
    conns = {}                            # conn -> label ('benign' or attack kind)
    alerted = collections.defaultdict(set)
    total_pkts, total_bytes, elapsed = 0, 0, 0.0

    for name in files:
        path = os.path.join(datadir, name)
        t = time.perf_counter()
        p = subprocess.run([ids, path, rules], capture_output=True, text=True, errors='replace')
        elapsed += time.perf_counter() - t
        alerts = collections.defaultdict(set)
        summary = None
        for line in p.stdout.splitlines():
            if m := ALERT.match(line): alerts[int(m[1])].add(int(m[2]))
            elif m := SUMMARY.match(line): summary = int(m[1])
        assert summary is not None, f'{name}: no summary from nids: {p.stderr.strip()}'

        for i, f in packets(path):
            total_pkts += 1
            total_bytes += len(f)
            if len(f) < 34 or f[12:14] != b'\x08\x00':
                mix[{b'\x86\xdd': 'IPv6', b'\x08\x06': 'ARP', b'\x81\x00': 'VLAN'}.get(f[12:14], 'other L2')] += 1
                continue
            if f[23] != 6:
                mix[{17: 'IPv4 UDP', 1: 'IPv4 ICMP'}.get(f[23], 'IPv4 other')] += 1
                continue
            mix['IPv4 TCP (inspected)'] += 1
            t0 = 14 + (f[14] & 15) * 4
            if struct.unpack_from('!H', f, 20)[0] & 0x1FFF or len(f) < t0 + 20:
                continue
            sp, dp = struct.unpack_from('!HH', f, t0)
            pl = f[t0 + (f[t0 + 12] >> 4) * 4:14 + struct.unpack_from('!H', f, 16)[0]]
            if not pl:
                continue
            src, dst = ip(f[26:30]), ip(f[30:34])
            key = tuple(sorted([(src, sp), (dst, dp)]))
            tcp_bytes[min(sp, dp)] += len(pl)
            label = conns.setdefault((name, key), 'benign')
            if {src, dst} == {ATTACKER, VICTIM}:
                for kind, marker in KINDS:   # a connection takes its most specific attack kind
                    if marker in pl[:2048] and RANK[kind] < RANK.get(label, len(KINDS)):
                        label = kind
                conns[(name, key)] = 'attacker page loads' if label == 'benign' else label
            if i in alerts:
                alerted[(name, key)] |= alerts[i]

    out = []
    emit = out.append
    pct = lambda a, b, d=1: f'{100 * a / b:.{d}f}%' if b else 'n/a'
    emit('# nids on real traffic: CSE-CIC-IDS2018')
    emit('')
    emit(f'Thursday 22 Feb 2018, {len(files)} captures (the attacked web server + {len(files) - 1} other hosts), '
         f'{total_pkts:,} packets, {total_bytes / 1e9:.2f} GB. Rules: `{os.path.basename(rules)}` unchanged.')
    emit('')
    emit('## Detection (per TCP connection with payload)')
    emit('')
    emit('| Traffic | Connections | Alerted | Rate |')
    emit('|---|---|---|---|')
    by = collections.defaultdict(lambda: [0, 0])
    for c, label in conns.items():
        by[label][0] += 1
        by[label][1] += bool(alerted.get(c))
    for label in [k for k, _ in KINDS] + ['attacker page loads', 'benign']:
        n, a = by[label]
        rate = f'FPR {pct(a, n, 3)}' if label == 'benign' else f'TPR {pct(a, n)}'
        emit(f'| {"benign" if label == "benign" else "attack: " + label} | {n:,} | {a:,} | {rate} |')
    emit('')
    fp_sids = collections.Counter(s for c, sids in alerted.items() if conns[c] == 'benign' for s in sids)
    if fp_sids:
        emit('False positives by rule: ' + ', '.join(f'sid {s}: {n}' for s, n in fp_sids.most_common()) + '.')
        emit('')
    emit('## What nids could see')
    emit('')
    emit('| Packets | Share |')
    emit('|---|---|')
    for k, v in mix.most_common():
        emit(f'| {k} | {pct(v, total_pkts)} |')
    emit('')
    tls = sum(v for k, v in tcp_bytes.items() if k in (443, 993, 995, 465, 636, 22, 3389))
    emit(f'{pct(tls, sum(tcp_bytes.values()))} of TCP payload bytes are on encrypted ports '
         f'(443, 22, 3389, 993, 995, 465, 636), where content rules only see ciphertext.')
    emit('')
    emit(f'Throughput on this traffic: {total_pkts / elapsed / 1e6:.2f} M packets/s '
         f'({total_bytes * 8 / elapsed / 1e9:.2f} Gbit/s), process start-up included.')

    report = '\n'.join(out) + '\n'
    print(report)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CIC-IDS2018.md'), 'w') as f:
        f.write(report)


if __name__ == '__main__':
    if sys.argv[1:2] == ['fetch'] and len(sys.argv) == 3:
        fetch(sys.argv[2])
    elif sys.argv[1:2] == ['eval'] and len(sys.argv) == 5:
        evaluate(*sys.argv[2:5])
    else:
        sys.exit(__doc__)
