#!/usr/bin/env python3
"""Build the decode-differential corpus for the MELPS 740 module.

gen_corpus.py <outdir> [seed]
Writes <outdir>/data.bin (all records packed back to back), <outdir>/recs.txt ("<index> <offset>
<hex address>") and <outdir>/chunk*.bin (the packed records of each 0xE000-byte chunk, for MAME,
which is run on every chunk at base 0x1000). Record lengths come from MAME's own decoder (probed
one opcode at a time), so the MAME stream stays in step.
"""
import os, random, subprocess, sys

out = sys.argv[1]
seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
os.makedirs(out, exist_ok=True)
rnd = random.Random(seed)

def mame_len(op):
    p = os.path.join(out, 'probe.bin')
    open(p, 'wb').write(bytes([op, 0x12, 0x34, 0xEA, 0xEA, 0xEA]))
    lines = subprocess.run(['unidasm', p, '-arch', 'm740', '-basepc', '0x1000'],
                           capture_output=True, text=True).stdout.splitlines()
    return int(lines[1].split(':')[0], 16) - 0x1000

LEN = [mame_len(op) for op in range(256)]
recs = []
for op in range(256):
    n = LEN[op]
    if n == 1:
        recs.append(bytes([op]))
    elif n == 2:
        recs += [bytes([op, a]) for a in range(256)]
    else:
        for a in range(256):
            for b in list(range(0, 256, 17)) + [0x7f, 0x80, 0xff]:
                recs.append(bytes([op, a, b]))
for _ in range(120000):
    op = rnd.randrange(256)
    recs.append(bytes([op] + [rnd.randrange(256) for _ in range(LEN[op] - 1)]))

data = bytearray()
with open(os.path.join(out, 'recs.txt'), 'w') as rf:
    chunk, base, ci, cf = 0, 0x1000, 0, None
    cdata = bytearray()
    cbase = 0
    for i, r in enumerate(recs):
        if len(cdata) + 3 > 0xE000:
            open(os.path.join(out, 'chunk%03d.bin' % ci), 'wb').write(cdata)
            ci += 1
            cdata = bytearray()
        rf.write('%d %d %x\n' % (i, len(data), 0x1000 + len(cdata)))
        data += r
        cdata += r
    open(os.path.join(out, 'chunk%03d.bin' % ci), 'wb').write(cdata)
open(os.path.join(out, 'data.bin'), 'wb').write(data)
open(os.path.join(out, 'lens.txt'), 'w').write(' '.join(map(str, LEN)))
print('%d records, %d chunks' % (len(recs), ci + 1))
