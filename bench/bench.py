#!/usr/bin/env python3
"""nids benchmark harness -- stdlib only, deterministic (seed 1337).

usage: bench.py <ids> <ids_asan> <workdir>

Builds labeled pcaps, runs nids on them, scores its output against ground truth:
  1. detection   -- benign vs attack traffic: TPR / FPR / precision per variant
  2. matcher     -- alerts vs a Python reference (`sig in payload`)
  3. accuracy    -- parser edge cases: did it extract exactly the right payload?
  4. robustness  -- mutated/random packets + bad rules under ASan+UBSan
  5. throughput  -- 1M packets, median of 5 runs, vs number of rules
"""
import os, random, re, statistics, string, struct, subprocess, sys, time

R = random.Random(1337)
IDS, IDS_ASAN, WORK = sys.argv[1:4]
os.makedirs(WORK, exist_ok=True)

# ---------------------------------------------------------------- builders
def ipb(s): return bytes(map(int, s.split('.')))
def rip(): return f'10.{R.randrange(256)}.{R.randrange(256)}.{R.randrange(1, 255)}'
def rport(): return R.randrange(1024, 65535)
def txt(lo=1, hi=400): return ''.join(R.choices(string.ascii_letters + string.digits + ' ', k=R.randrange(lo, hi))).encode()

def tcp(payload=b'', sp=None, dp=80, flags=0x18, opts=b'', doff=None):
    if doff is None: doff = 5 + len(opts) // 4
    return struct.pack('!HHIIBBHHH', sp or rport(), dp, R.getrandbits(32), R.getrandbits(32),
                       doff << 4, flags, 65535, 0, 0) + opts + payload

def udp(payload, dp=53): return struct.pack('!HHHH', rport(), dp, 8 + len(payload), 0) + payload

def ipv4(l4, proto=6, src=None, dst=None, opts=b'', ihl=None, tlen=None, frag=0, ver=4):
    if ihl is None: ihl = 5 + len(opts) // 4
    if tlen is None: tlen = 20 + len(opts) + len(l4)
    return struct.pack('!BBHHHBBH4s4s', ver << 4 | ihl, 0, tlen & 0xFFFF, R.getrandbits(16), frag,
                       64, proto, 0, ipb(src or rip()), ipb(dst or rip())) + opts + l4

def ipv6(l4): return struct.pack('!IHBB16s16s', 6 << 28, len(l4), 6, 64, R.randbytes(16), R.randbytes(16)) + l4

def eth(l3, etype=0x0800, vlan=False):
    tag = struct.pack('!HH', 0x8100, 100) if vlan else b''
    f = bytes.fromhex('001122334455' '66778899aabb') + tag + struct.pack('!H', etype) + l3
    return f + bytes(max(0, 60 - len(f)))  # NICs pad short frames to 60 bytes

NOP4 = b'\x01' * 4

def tcp_payload(f):  # ground truth for well-formed frames we built ourselves
    if f[12:14] != b'\x08\x00' or f[23] != 6: return None
    t = 14 + (f[14] & 15) * 4
    return f[t + (f[t + 12] >> 4) * 4:14 + struct.unpack('!H', f[16:18])[0]]

# ------------------------------------------------------- pcap, rules, run
def write_pcap(path, pkts):  # pkts: [(frame, orig_len|None, ...)]
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (fr, orig, *_) in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, i % 1000 * 1000, len(fr), orig or len(fr)))
            f.write(fr)

def write_rules(path, rules):  # rules: [(sid, content_bytes)]
    esc = lambda c: ''.join(chr(b) if 0x21 <= b <= 0x7E and b != 0x7C else f'|{b:02x}|' for b in c)
    with open(path, 'w') as f:
        f.writelines(f'{sid} "r{sid}" {esc(c)}\n' for sid, c in rules)

PKT = re.compile(r'^\[(\d+)\] TCP ')
PAY = re.compile(r'^      payload: (\d+) bytes  "(.*)"$')
ALR = re.compile(r'^ALERT pkt=(\d+) sid=(\d+) msg=".*" \S+ -> \S+ offset=(\d+)$')
SUM = re.compile(r'^(\d+) packets, \d+ IPv4, \d+ TCP, (\d+) alerts$')

def run(binary, path, rules, verbose=False, env=None):
    p = subprocess.run([binary] + (['-v'] if verbose else []) + [path, rules], capture_output=True, env=env)
    got, alerts, other, cur, total = {}, {}, [], None, None
    for line in p.stdout.decode('latin-1').splitlines():
        if m := PKT.match(line): cur = int(m[1])
        elif m := PAY.match(line): got[cur] = (int(m[1]), m[2])
        elif m := ALR.match(line): alerts.setdefault(int(m[1]), {})[int(m[2])] = int(m[3])
        elif m := SUM.match(line): total = int(m[1])
        elif line and line != '---': other.append(line)
    other += [l for l in p.stderr.decode('latin-1').splitlines() if l]
    return p, got, alerts, other, total

def preview(b): return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:40])  # C-locale isprint
def ok(got, want): return got is None if want is None else got == (len(want), preview(want))
def pct(a, b, d=1): return f'{100 * a / b:.{d}f}%' if b else 'n/a'

out = []
def emit(s=''): print(s); out.append(s)

# ============================================================ 1. detection
SIGS = {1001: b'EVIL_PAYLOAD_SIGNATURE_v1', 1002: b'/../../', 1003: b"' OR '1'='1",
        1004: b'<script>alert(document.cookie)', 1005: b'() { :; };', 1006: b'${jndi:',
        1007: b'cmd.exe /c', 1008: b'\x90' * 16}            # mirrors rules/default.rules
RULES = f'{WORK}/bench.rules'
write_rules(RULES, SIGS.items())

PATHS = ['/', '/index.html', '/api/v1/users', '/static/app.js', '/login', '/search?q=weather', '/img/logo.png']
def benign():
    k = R.randrange(6)
    if k == 0: return eth(ipv4(tcp(f'GET {R.choice(PATHS)} HTTP/1.1\r\nHost: www.example{R.randrange(50)}.com\r\n'
                                   'User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n'.encode())))
    if k == 1: return eth(ipv4(tcp(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head>'
                                   b'<script src="/app.js"></script></head><body>' + txt() + b'</body></html>', sp=80, dp=rport())))
    if k == 2: n = R.randrange(20, 1400); return eth(ipv4(tcp(b'\x17\x03\x03' + struct.pack('!H', n) + R.randbytes(n), dp=443)))
    if k == 3: return eth(ipv4(tcp(b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n', dp=22)))
    if k == 4: return eth(ipv4(tcp(flags=R.choice([0x02, 0x12, 0x10, 0x11]))))       # handshake / ack / fin
    return eth(ipv4(udp(b'\x12\x34\x01\x00\x00\x01' + bytes(6) + b'\x07example\x03com\x00\x00\x01\x00\x01'), proto=17))

# Benign pages that *quote* attack strings (security blogs, docs) -- the classic
# false-positive source for content rules. HTML-escaped quotes can't match.
DOCS = [b'<p>Log4Shell (CVE-2021-44228) fires on input like <code>${jndi:ldap://host/a}</code>.</p>',
        b"<p>The classic SQL injection test is <code>' OR '1'='1</code> in a login form.</p>",
        b'<p>Shellshock payloads begin with <code>() { :; };</code> inside an HTTP header.</p>',
        b'<p>On Windows, run <code>cmd.exe /c dir</code> to list a folder.</p>',
        b'<p>Path traversal looks like <code>/../../etc/passwd</code> in a URL.</p>',
        b'<p>XSS can steal sessions via <code>&lt;script&gt;alert(document.cookie)</code>.</p>',
        b'<p>Patch your SMB servers and block port 445 at the edge.</p>']
def doc_page(d): return eth(ipv4(tcp(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><article>'
                                     + txt(0, 200) + d + txt(0, 200) + b'</article></body></html>', sp=80, dp=rport())))

def attack(variant, sig):
    """-> [(frame, None, ideal_payload|None)] for one attack event"""
    pre = b'GET /q?x=' + txt(0, 120)
    pl, off = pre + sig + b' HTTP/1.1\r\nHost: victim\r\n\r\n', len(pre)
    if variant == 'plain':          return [(eth(ipv4(tcp(pl))), None, pl)]
    if variant == 'ip+tcp options': return [(eth(ipv4(tcp(pl, opts=NOP4 * R.randrange(1, 11)), opts=NOP4 * R.randrange(1, 11))), None, pl)]
    if variant == '802.1Q VLAN':    return [(eth(ipv4(tcp(pl)), vlan=True), None, pl)]
    if variant == 'IPv6':           return [(eth(ipv6(tcp(pl)), 0x86dd), None, pl)]
    if variant == 'UDP':            return [(eth(ipv4(udp(pl), proto=17)), None, pl)]
    if variant == 'IP fragmented':  # signature split across 2 fragments (cut 4 bytes into it)
        pad = b'x' * ((4 - 20 - off) % 8)
        pl, off = pre + pad + sig + b' HTTP/1.1\r\nHost: victim\r\n\r\n', off + len(pad)
        seg = tcp(pl); cut = 20 + off + 4
        return [(eth(ipv4(seg[:cut], frag=0x2000)), None, pl[:cut - 20]),
                (eth(ipv4(seg[cut:], frag=cut // 8)), None, None)]
    if variant == 'TCP segmented':  # signature split across 2 segments
        c = off + len(sig) // 2
        return [(eth(ipv4(tcp(pl[:c]))), None, pl[:c]), (eth(ipv4(tcp(pl[c:]))), None, pl[c:])]

VARIANTS = ['plain', 'ip+tcp options', '802.1Q VLAN', 'IPv6', 'UDP', 'IP fragmented', 'TCP segmented']
REPS = 20

pkts, events = [], []  # events: (kind, label, first_idx, last_idx, sid|None)
def add(kind, label, plist, sid=None):
    events.append((kind, label, len(pkts) + 1, len(pkts) + len(plist), sid)); pkts.extend(plist)

for fr in (benign() for _ in range(10000)): add('benign', 'normal web traffic', [(fr, None, tcp_payload(fr))])
for fr in (doc_page(DOCS[i % len(DOCS)]) for i in range(700)): add('benign', 'pages quoting attack strings', [(fr, None, tcp_payload(fr))])
for v in VARIANTS:
    for sid, s in SIGS.items():
        for _ in range(REPS): add('attack', v, attack(v, s), sid)
victim = '10.0.0.10'
add('other', 'port scan (1000 SYNs)', [(eth(ipv4(tcp(dp=p, flags=0x02), src='10.66.6.6', dst=victim)), None, b'') for p in range(1, 1001)])
add('other', 'SYN flood (5000 SYNs)', [(eth(ipv4(tcp(flags=0x02), dst=victim)), None, b'') for _ in range(5000)])

write_pcap(f'{WORK}/detect.pcap', pkts)
_, got, alerts, junk, total = run(IDS, f'{WORK}/detect.pcap', RULES, verbose=True)
assert total == len(pkts) and not junk, (total, len(pkts), junk[:3])

def fired(a, b, sid=None):
    hits = [alerts.get(i, {}) for i in range(a, b + 1)]
    return any(h and (sid is None or sid in h) for h in hits)

atk = [e for e in events if e[0] == 'attack']
ben = [e for e in events if e[0] == 'benign']
tp = sum(fired(a, b, sid) for _, _, a, b, sid in atk)
fp = sum(fired(a, b) for _, _, a, b, _ in ben)
emit('## 1. Detection (signature rules, `rules/default.rules` content)')
emit()
emit(f'{len(pkts):,} packets: {len(ben):,} benign, {len(atk):,} payload attacks '
     f'({len(VARIANTS)} delivery variants x {len(SIGS)} signatures x {REPS}), plus a port scan and a SYN flood.')
emit(f'Alerts raised: {sum(len(v) for v in alerts.values()):,}')
emit()
emit('| Traffic | Events | Alerted | Rate |')
emit('|---|---|---|---|')
for v in VARIANTS:
    evs = [e for e in atk if e[1] == v]; d = sum(fired(a, b, sid) for _, _, a, b, sid in evs)
    emit(f'| attack: {v} | {len(evs)} | {d} | TPR {pct(d, len(evs))} |')
for lab in ['normal web traffic', 'pages quoting attack strings']:
    evs = [e for e in ben if e[1] == lab]; f = sum(fired(a, b) for _, _, a, b, _ in evs)
    emit(f'| benign: {lab} | {len(evs):,} | {f} | FPR {pct(f, len(evs), 2)} |')
for e in events:
    if e[0] == 'other': emit(f'| {e[1]} | 1 | {int(fired(e[2], e[3]))} | not a content attack (no payload) |')
emit()
plain = [e for e in atk if e[1] in ('plain', 'ip+tcp options')]
dp = sum(fired(a, b, sid) for _, _, a, b, sid in plain)
emit(f'- **TPR, plain delivery** (no evasion): {dp}/{len(plain)} = **{pct(dp, len(plain))}**')
emit(f'- **TPR, all {len(VARIANTS)} delivery variants**: {tp}/{len(atk)} = **{pct(tp, len(atk))}**')
emit('- FPR is reported per benign class only: a blended FPR or precision would just reflect the class mix chosen here.')
emit()

# ======================================================== 2. matcher check
def reference_check(pkt_list, got, alerts, sigs):
    """alerts must equal {sid: payload.find(sig)} on every correctly parsed payload, and be empty elsewhere"""
    agree = 0
    for i, (_, _, want) in enumerate(pkt_list, 1):
        exp = {sid: want.find(s) for sid, s in sigs.items() if s in want} if want is not None and ok(got.get(i), want) else {}
        agree += alerts.get(i, {}) == exp
    return agree

agree_detect = reference_check(pkts, got, alerts, SIGS)
# Stress: many short, overlapping rules over a 3-letter alphabet (suffix links, duplicates, nesting)
stress_sigs = {i: ''.join(R.choices('abc', k=R.randrange(1, 7))).encode() for i in range(1, 301)}
stress_sigs[301] = stress_sigs[1]                                   # duplicate content
stress = [(eth(ipv4(tcp(p))), None, p) for p in (''.join(R.choices('abc', k=R.randrange(0, 300))).encode() for _ in range(3000))]
write_rules(f'{WORK}/stress.rules', stress_sigs.items())
write_pcap(f'{WORK}/stress.pcap', stress)
_, sgot, salerts, _, _ = run(IDS, f'{WORK}/stress.pcap', f'{WORK}/stress.rules', verbose=True)
agree_stress = reference_check(stress, sgot, salerts, stress_sigs)
emit('## 2. Matcher correctness (vs Python reference: same sids, same offsets)')
emit()
emit(f'- Detection set ({len(SIGS)} rules): {agree_detect:,}/{len(pkts):,} packets agree = **{pct(agree_detect, len(pkts))}**')
emit(f'- Overlap stress set ({len(stress_sigs)} rules of 1-6 bytes over "abc", {sum(len(v) for v in salerts.values()):,} alerts): '
     f'{agree_stress:,}/{len(stress):,} packets agree = **{pct(agree_stress, len(stress))}**')
emit()

# ============================================================= 3. accuracy
def c_plain():    p = txt(); return eth(ipv4(tcp(p))), None, p
def c_ipopt():    p = txt(); return eth(ipv4(tcp(p), opts=NOP4 * R.randrange(1, 11))), None, p
def c_tcpopt():   p = txt(); return eth(ipv4(tcp(p, opts=NOP4 * R.randrange(1, 11)))), None, p
def c_both():     p = txt(); return eth(ipv4(tcp(p, opts=NOP4 * R.randrange(1, 11)), opts=NOP4 * R.randrange(1, 11))), None, p
def c_pad():      return eth(ipv4(tcp(flags=0x02))), None, b''
def c_tlenbig():  p = txt(6); return eth(ipv4(tcp(p), tlen=40 + len(p) + R.randrange(1, 500))), None, p
def c_tpay():     p = txt(40); f = eth(ipv4(tcp(p))); c = R.randrange(55, len(f)); return f[:c], len(f), p[:c - 54]
def c_frag1():    p = txt(40); seg = tcp(p); c = 8 * R.randrange(3, len(seg) // 8); return eth(ipv4(seg[:c], frag=0x2000)), None, seg[20:c]
def c_udp():      return eth(ipv4(udp(txt()), proto=17)), None, None
def c_arp():      return eth(R.randbytes(28), 0x0806), None, None
def c_thdr():     f = eth(ipv4(tcp(txt()))); c = R.randrange(34, 54); return f[:c], len(f), None
def c_ihl():      return eth(ipv4(tcp(txt()), ihl=R.randrange(0, 5))), None, None
def c_doff():     return eth(ipv4(tcp(txt(), doff=R.randrange(0, 5)))), None, None
def c_tlensm():   return eth(ipv4(tcp(txt()), tlen=R.randrange(1, 40))), None, None
def c_ver():      return eth(ipv4(tcp(txt()), ver=R.choice([0, 5, 6, 15]))), None, None
def c_fragn():    p = txt(40); seg = tcp(p); c = 8 * R.randrange(3, len(seg) // 8); return eth(ipv4(seg[c:], frag=c // 8)), None, None
def c_vlan():     p = txt(); return eth(ipv4(tcp(p)), vlan=True), None, p
def c_ipv6():     p = txt(); return eth(ipv6(tcp(p)), 0x86dd), None, p
def c_tso():      p = txt(); return eth(ipv4(tcp(p), tlen=0)), None, p

CASES = [  # (group, name, expected behaviour, builder)
    ('well-formed', 'plain TCP', 'extract payload', c_plain),
    ('well-formed', 'IP options (IHL 6-15)', 'extract payload', c_ipopt),
    ('well-formed', 'TCP options (doff 6-15)', 'extract payload', c_tcpopt),
    ('well-formed', 'IP + TCP options', 'extract payload', c_both),
    ('well-formed', 'Ethernet padding (60B SYN)', 'extract 0 bytes, ignore padding', c_pad),
    ('well-formed', 'snaplen-truncated payload', 'extract captured bytes', c_tpay),
    ('well-formed', 'total_len > captured', 'clamp to caplen', c_tlenbig),
    ('well-formed', 'first IP fragment (MF)', 'extract partial payload', c_frag1),
    ('well-formed', 'UDP', 'skip', c_udp),
    ('well-formed', 'ARP', 'skip', c_arp),
    ('malformed', 'truncated inside TCP header', 'reject', c_thdr),
    ('malformed', 'IHL < 5', 'reject', c_ihl),
    ('malformed', 'TCP data offset < 5', 'reject', c_doff),
    ('malformed', 'total_len < headers', 'reject', c_tlensm),
    ('malformed', 'IP version != 4', 'reject', c_ver),
    ('malformed', 'non-first IP fragment', "don't parse as TCP header", c_fragn),
    ('coverage', '802.1Q VLAN TCP', 'extract payload', c_vlan),
    ('coverage', 'IPv6 TCP', 'extract payload', c_ipv6),
    ('coverage', 'TSO (total_len = 0)', 'extract captured payload', c_tso),
]
N = 200
acc_pkts, acc_case = [], []
for ci, case in enumerate(CASES):
    for _ in range(N): acc_pkts.append(case[3]()); acc_case.append(ci)
write_pcap(f'{WORK}/accuracy.pcap', acc_pkts)
_, got, _, _, total = run(IDS, f'{WORK}/accuracy.pcap', RULES, verbose=True)
assert total == len(acc_pkts)

emit('## 3. Parser accuracy (exact payload extraction vs ground truth)')
emit()
emit(f'{N} randomized packets per case, {len(acc_pkts):,} total.')
emit()
emit('| Group | Case | Expected | Correct |')
emit('|---|---|---|---|')
by_group = {}
for ci, (g, name, exp, _) in enumerate(CASES):
    c = sum(ok(got.get(i + 1), acc_pkts[i][2]) for i in range(len(acc_pkts)) if acc_case[i] == ci)
    by_group.setdefault(g, [0, 0]); by_group[g][0] += c; by_group[g][1] += N
    emit(f'| {g} | {name} | {exp} | {c}/{N} ({pct(c, N)}) |')
emit()
for g, (c, n) in by_group.items(): emit(f'- **{g}**: {c:,}/{n:,} = **{pct(c, n)}**')
emit()

# =========================================================== 4. robustness
def mutate(f):
    f = bytearray(f)
    for _ in range(R.randrange(1, 9)): f[R.randrange(min(len(f), 80))] = R.randrange(256)
    if R.random() < 0.3: f = f[:R.randrange(len(f) + 1)]
    return bytes(f)
templates = [c[3]()[0] for c in CASES for _ in range(20)] + [p[0] for p in pkts[10000:12000]]
fuzz = [(mutate(R.choice(templates)), None) for _ in range(200000)]
for _ in range(20000):  # random frames that at least claim IPv4/TCP
    f = bytearray(R.randbytes(R.randrange(0, 120)))
    if len(f) > 23: f[12:14] = b'\x08\x00'; f[23] = 6
    fuzz.append((bytes(f), None))
write_pcap(f'{WORK}/fuzz.pcap', fuzz)
env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1', UBSAN_OPTIONS='print_stacktrace=1')
p, _, _, other, total = run(IDS_ASAN, f'{WORK}/fuzz.pcap', RULES, env=env)
san = [l for l in other if 'runtime error' in l or 'Sanitizer' in l]

BAD_RULES = ['1 "x" |0d 0|', '1 "x" |0d', '1 "x"', '1 x content', 'abc "x" c', '1 "' + 'm' * 300 + '" c',
             '1 "x" ' + 'A' * 257, '1 "x" ||', '1 "x" |zz|', '1 "x" ' + 'B' * 2000, '"x" c', '1 "" c']
bad_ok = 0
for i, r in enumerate(BAD_RULES):
    with open(f'{WORK}/bad{i}.rules', 'w') as f: f.write(r + '\n')
    q, *_, rother, _ = run(IDS_ASAN, f'{WORK}/detect.pcap', f'{WORK}/bad{i}.rules', env=env)
    bad_ok += q.returncode == 1 and any('error:' in l for l in rother) and not any('Sanitizer' in l or 'runtime error' in l for l in rother)

emit('## 4. Robustness (ASan + UBSan + LeakSanitizer build)')
emit()
emit(f'- Malformed packets fed: {len(fuzz):,} (200,000 mutated + 20,000 random), all scanned against the rules')
emit(f'- Packets processed: {total:,}' if total else '- Packets processed: run aborted')
emit(f'- Exit code: {p.returncode}; memory-safety / UB / leak reports: **{len(san)}**')
for l in san[:5]: emit(f'  - `{l}`')
emit(f'- Malformed rule files rejected cleanly (exit 1, error message, no sanitizer report): **{bad_ok}/{len(BAD_RULES)}**')
emit()

# =========================================================== 5. throughput
pool = [(benign(), None) for _ in range(10000)]
big = pool * 100
write_pcap(f'{WORK}/big.pcap', big)
nbytes = sum(len(f) for f, _ in big)

write_pcap(f'{WORK}/empty.pcap', [])

def bench(pcap, rules, n=5):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); subprocess.run([IDS, pcap, rules], stdout=subprocess.DEVNULL, check=True)
        ts.append(time.perf_counter() - t)
    return statistics.median(ts)

emit('## 5. Throughput (-O2, alerts only, stdout -> /dev/null, warm cache, median of 5)')
emit()
emit(f'{len(big):,} packets / {nbytes / 1e6:.0f} MB of benign traffic. Random rules are 8-16 printable bytes.')
emit('Startup = loading rules + building the automaton (timed on an empty capture); scan = total - startup.')
emit()
emit('| Rules | Startup | Total | Scan-only packets/s | Scan-only Gbit/s |')
emit('|---|---|---|---|---|')
for n in [0, 8, 100, 1000, 5000]:
    path = RULES if n == 8 else f'{WORK}/rand{n}.rules'
    if n != 8: write_rules(path, [(i, txt(8, 17).replace(b' ', b'_')) for i in range(1, n + 1)])
    st, tot = bench(f'{WORK}/empty.pcap', path), bench(f'{WORK}/big.pcap', path)
    emit(f'| {n:,}{" (default set)" if n == 8 else ""} | {st * 1000:.0f} ms | {tot:.3f}s | '
         f'{len(big) / (tot - st) / 1e6:.2f} M | {nbytes * 8 / (tot - st) / 1e9:.2f} |')

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'RESULTS.md'), 'w') as f:
    f.write('# nids benchmark results (Phase 2)\n\n' + '\n'.join(out) + '\n')
