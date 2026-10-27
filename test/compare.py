#!/usr/bin/env python3
"""Compare the Ghidra decode of the corpus with MAME's `unidasm -arch m740`.

compare.py <corpusdir> <ghidra-dump.txt> <variant: default|wit|muldiv> [--show N]

Buckets every record: exact (after normalising spelling), explained difference classes, or
unexplained. Exit status 1 if anything is unexplained.
"""
import collections, os, re, subprocess, sys

corp, gdump, variant = sys.argv[1:4]
show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 10
LEN = list(map(int, open(os.path.join(corp, 'lens.txt')).read().split()))
data = open(os.path.join(corp, 'data.bin'), 'rb').read()
recs = [l.split() for l in open(os.path.join(corp, 'recs.txt'))]

# MAME: run every chunk at base 0x1000
mame = {}
idx = 0
for ci in range(1000):
    p = os.path.join(corp, 'chunk%03d.bin' % ci)
    if not os.path.exists(p):
        break
    out = subprocess.run(['unidasm', p, '-arch', 'm740', '-basepc', '0x1000'],
                         capture_output=True, text=True).stdout.splitlines()
    for line in out:
        addr, rest = line.split(':', 1)
        toks = rest.split()
        r = recs[idx]
        n = LEN[data[int(r[1])]]
        assert int(addr, 16) == int(r[2], 16), (idx, addr, r)
        mame[idx] = ' '.join(toks[n:])
        idx += 1
assert idx == len(recs), (idx, len(recs))

def num(m):
    s = m.group(1) or m.group(2)
    return str(int(s, 16))

def norm(t):
    t = t.lower().replace(' ', '')
    t = re.sub(r'\\+0x(?:1f|ff)([0-9a-f]{2})', r'\\$\1', t)   # special page (page differs per family)
    t = re.sub(r'0x([0-9a-f]+)|\$([0-9a-f]+)', num, t)
    t = re.sub(r'^(seb|clb|bbs|bbc)#', r'\1', t)
    return t

ghidra = {}
for l in open(gdump):
    i, n, text = l.rstrip('\n').split(' ', 2)
    ghidra[int(i)] = (int(n), text)

# reserved opcodes: the manual defines no instruction, MAME decodes the 6502 leftovers
RESERVED_M = re.compile(r'^(kil|shx|shy|nop)\b')
buckets = collections.Counter()
examples = collections.defaultdict(list)
for i, r in enumerate(recs):
    op = data[int(r[1])]
    mt = mame[i]
    gn, gt = ghidra[i]
    if gt == 'BAD':
        if RESERVED_M.match(mt):
            cls = 'both invalid / MAME decodes a 6502 leftover that the manual does not define'
        elif op == 0xC2 or op == 0xE2 or op == 0x62:
            cls = 'bad'
        else:
            cls = 'UNEXPLAINED: Ghidra rejects, MAME: ' + mt.split()[0]
    elif op in (0xC2, 0xE2, 0x62) and gt.split()[0].lower() in ('fst', 'slw', 'wit', 'mul', 'div') \
            and gn == (2 if op in (0x62,) or gt.startswith('DIV') else 1):
        cls = 'manual-only instruction (%s) that MAME decodes as %s' % (gt.split()[0], mt.split()[0])
    elif gn != LEN[op]:
        cls = 'UNEXPLAINED: length %d vs %d' % (gn, LEN[op])
    elif norm(gt) == norm(mt):
        cls = 'exact'
    else:
        cls = None
        mn = gt.split()[0].lower()
        # instructions MAME does not know (manual: FST/SLW, WIT, MUL, DIV)
        if op in (0xC2, 0xE2, 0x62) and mn in ('fst', 'slw', 'wit', 'mul', 'div'):
            cls = 'manual-only instruction (%s) that MAME decodes as %s' % (mn.upper(), mt.split()[0])
        else:
            cls = 'UNEXPLAINED: %s | %s' % (gt, mt)
    if cls == 'bad':
        # C2 / E2 / 62 that Ghidra rejects: legal only in some variants
        expected_bad = (op == 0x62 and variant != 'muldiv') or (op == 0xE2 and variant == 'wit') \
            or (op == 0xC2 and False)
        cls = 'manual-reserved in this variant (MAME: %s)' % mt.split()[0] if expected_bad else \
            'UNEXPLAINED: Ghidra rejects %02x, MAME: %s' % (op, mt)
    buckets[cls] += 1
    if len(examples[cls]) < show:
        examples[cls].append('%s  ghidra=%r  mame=%r' % (r[2], gt, mt))

total = len(recs)
bad = 0
print('variant %s: %d records' % (variant, total))
for k, v in sorted(buckets.items(), key=lambda kv: -kv[1]):
    print('%8d  %s' % (v, k))
    if k.startswith('UNEXPLAINED'):
        bad += v
        for e in examples[k]:
            print('            ', e)
print('unexplained: %d' % bad)
sys.exit(1 if bad else 0)
