#!/usr/bin/env python3
"""Real-code checks for the MELPS 740 module.

real_check.py <workdir> <ghs-wrapper> <ghidra-analysis-prefix-osi> <variant>
 A. OSI/MS BASIC as ported to the MELPS 740 (SBC740), assembled by ca65: every instruction of the
    ca65 listing is decoded by Ghidra and by MAME; length and mnemonic must equal the assembler's,
    the text must equal MAME's. Then the auto-analysed Ghidra listing is checked against the
    assembler listing (every instruction Ghidra made starts at an assembler instruction boundary).
 B. mnaberez/m740dasm's end-to-end test program (hand-written, one line per opcode, BSD-3):
    mnemonic and length of Ghidra's decode of each line's bytes.
 C. The SBC740 L-chika blinker assembled by AS.
"""
import os, re, subprocess, sys, collections

work, ghs, prefix, variant = sys.argv[1:5]
LANG = {'default': 'MELPS740:LE:16:default', 'wit': 'MELPS740:LE:16:wit',
        'muldiv': 'MELPS740:LE:16:muldiv'}[variant]
fails = 0

def ghidra_decode(recs, tag):
    """recs: list of (bytes, address)"""
    data = b''.join(r for r, a in recs)
    p = os.path.join(work, tag)
    open(p + '.bin', 'wb').write(data)
    off = 0
    with open(p + '.recs', 'w') as f:
        for i, (r, a) in enumerate(recs):
            f.write('%d %d %x\n' % (i, off, a))
            off += len(r)
    subprocess.run([ghs, 'raw', LANG, os.path.join(work, 'z.bin'), 'DumpRecs.java', p + '.recs',
                    p + '.bin', p + '.out'], check=True)
    res = []
    for l in open(p + '.out'):
        i, n, t = l.rstrip('\n').split(' ', 2)
        res.append((int(n), t))
    return res

def mame_runs(recs):
    """MAME text per record; contiguous records are disassembled in one run."""
    out = [None] * len(recs)
    i = 0
    tmp = os.path.join(work, 'mame_run.bin')
    while i < len(recs):
        j = i
        while j + 1 < len(recs) and recs[j + 1][1] == recs[j][1] + len(recs[j][0]):
            j += 1
        open(tmp, 'wb').write(b''.join(r for r, a in recs[i:j + 1]))
        lines = subprocess.run(['unidasm', tmp, '-arch', 'm740', '-basepc', '0x%x' % recs[i][1]],
                               capture_output=True, text=True).stdout.splitlines()
        assert len(lines) == j - i + 1, (i, j, len(lines))
        for k, line in enumerate(lines):
            n = len(recs[i + k][0])
            out[i + k] = ' '.join(line.split(':', 1)[1].split()[n:])
        i = j + 1
    return out

def num(m):
    return str(int(m.group(1) or m.group(2), 16))

def norm(t):
    t = t.lower().replace(' ', '')
    t = re.sub(r'\\+0x(?:1f|ff)([0-9a-f]{2})', r'\\$\1', t)
    t = re.sub(r'0x([0-9a-f]+)|\$([0-9a-f]+)', num, t)
    t = re.sub(r'^(seb|clb|bbs|bbc)#', r'\1', t)
    return t

MNEM = set('adc and asl bbc bbs bcc bcs beq bit bmi bne bpl bra brk bvc bvs clb clc cld cli clt clv cmp '
           'com cpx cpy dec dex dey div eor fst inc inx iny jmp jsr lda ldm ldx ldy lsr mul nop ora pha '
           'php pla plp rol ror rrf rti rts sbc seb sec sed sei set slw sta stp stx sty tax tay tst tsx '
           'txa txs tya wit'.split())

# ---------------------------------------------------------------- A
truth = []        # (bytes, addr, mnemonic)
bytedir = set()    # addresses of .byte directives (hand-encoded opcodes, BIT-skip tricks)
LONG = {'jeq': 'bne', 'jne': 'beq', 'jcc': 'bcs', 'jcs': 'bcc', 'jmi': 'bpl', 'jpl': 'bmi',
        'jvc': 'bvs', 'jvs': 'bvc'}     # ca65 "longbranch" macros: branch over a JMP
pending = None
for l in open(os.path.join(work, 'osi.lst'), errors='replace'):
    m = re.match(r'^([0-9A-F]{6})\s+\d+\s{2}((?:[0-9A-F]{2} )+)\s*(.*)$', l.rstrip('\n'))
    if not m:
        continue
    src = m.group(3).split(';')[0].strip()
    toks = src.split()
    b = bytes.fromhex(m.group(2).replace(' ', ''))
    if not toks:
        if pending is not None:       # continuation line of a macro expansion
            pb, pa, pmn = pending
            pb += b
            a = pa
            truth.append((pb[:2], a, LONG[pmn]))
            truth.append((pb[2:], a + 2, 'jmp'))
            pending = None
        continue
    mn = toks[0].lower()
    if mn in LONG:
        pending = (b, int(m.group(1), 16), mn)
        continue
    if mn in MNEM:
        truth.append((b, int(m.group(1), 16), mn))
    elif mn == '.byte':
        for k in range(len(b)):
            bytedir.add(int(m.group(1), 16) + k)
print('A. ca65 listing: %d instructions' % len(truth))
dec = ghidra_decode([(b, a) for b, a, _ in truth], 'a_gh')
mame = mame_runs([(b, a) for b, a, _ in truth])
bad = 0
exact = 0
for (b, a, mn), (n, t), mt in zip(truth, dec, mame):
    if n != len(b) or t.split()[0].lower() != mn or norm(t) != norm(mt):
        bad += 1
        if bad <= 15:
            print('   MISMATCH %04x %s asm=%s ghidra=%r mame=%r' % (a, b.hex(), mn, t, mt))
    else:
        exact += 1
print('   %d of %d identical to the assembler (length, mnemonic) and to MAME (full text); %d differ' %
      (exact, len(truth), bad))
fails += bad

tmap = {a: (b, mn) for b, a, mn in truth}
dis = [l.split(' ', 2) for l in open(prefix + '.dis')]
onbound = off = 0
offlist = []
for addr, hexb, text in dis:
    a = int(addr, 16)
    if a in tmap and tmap[a][0].hex() == hexb:
        onbound += 1
    else:
        off += 1
        offlist.append((a, hexb, text.strip()))
print('   Ghidra analysis: %d instructions, %d at assembler instruction boundaries with the same bytes, %d not' %
      (len(dis), onbound, off))
for a, h, t in offlist[:12]:
    ins = [(x, tmap[x]) for x in range(a - 2, a + 1) if x in tmap and x < a and x + len(tmap[x][0]) > a]
    print('     %04x %s %s   (inside assembler instruction %s)' % (a, h, t,
          ' '.join('%04x %s' % (x, v[0].hex()) for x, v in ins) or 'none: data'))
# each such instruction must lie in the middle of an assembler instruction (BIT-skip tricks) or in data
unex = 0
data_ok = 0
for a, h, t in offlist:
    if a < 0x0100 or a >= 0xffff:
        data_ok += 1      # zero-page code copied at run time / vector table area
        continue
    inside = any(x in tmap and x + len(tmap[x][0]) > a for x in (a - 1, a - 2))
    if a in bytedir:
        data_ok += 1      # starts on a .byte (hand-encoded opcode or a BIT-skip trick)
        continue
    if not inside:
        unex += 1
        print('   UNEXPLAINED: Ghidra instruction %04x %s %s is neither inside nor on an assembler instruction' % (a, h, t))
print('   not at assembler instruction boundaries: %d start on a .byte (hand-encoded opcode or BIT-skip trick) or in zero page, %d inside another instruction, %d unexplained' %
      (data_ok, off - data_ok - unex, unex))
fails += unex

# ---------------------------------------------------------------- B
recs = []
src = []
addr = 0x8000
for l in open(os.path.join(work, 'testprog.asm')):
    m = re.match(r'^\s+([a-z]{3})\b([^;]*);([0-9a-f ]+)\s*(.*)$', l)
    if not m:
        continue
    b = bytes.fromhex(m.group(3).replace(' ', ''))
    recs.append((b, addr))
    src.append((m.group(1), m.group(2).strip(), m.group(4).strip()))
    addr += len(b)
dec = ghidra_decode(recs, 'b_gh')
bad = 0
variant_only = 0
for (b, a), (mn, ops, cm), (n, t) in zip(recs, src, dec):
    ok_here = {'mul': variant == 'muldiv', 'div': variant == 'muldiv', 'wit': variant != 'default',
               'fst': variant == 'default', 'slw': variant == 'default'}.get(mn, True)
    if not ok_here:
        variant_only += 1     # family-specific opcode this language does not define (or defines differently)
        continue
    if n != len(b) or t.split()[0].lower() != mn:
        bad += 1
        print('   B MISMATCH %04x %s test=%s %s ghidra=%r' % (a, b.hex(), mn, ops, t))
print('B. m740dasm test program: %d lines (one per opcode form), %d differ in mnemonic or length (%d MUL/DIV/WIT/FST/SLW lines belong to other families)' % (len(recs), bad, variant_only))
fails += bad

# ---------------------------------------------------------------- C
recs = []
src = []
for l in open(os.path.join(work, 'lchika_src.lst'), errors='replace'):
    m = re.match(r'^\s*\d+/\s*([0-9A-F]+) :\s+((?:[0-9A-F]{2} ?)+)\s+\t(\w+)', l)
    if m and m.group(3).lower() in MNEM:
        recs.append((bytes.fromhex(m.group(2).replace(' ', '')), int(m.group(1), 16)))
        src.append(m.group(3).lower())
dec = ghidra_decode(recs, 'c_gh')
mame = mame_runs(recs)
bad = sum(1 for (b, a), mn, (n, t), mt in zip(recs, src, dec, mame)
          if n != len(b) or t.split()[0].lower() != mn or norm(t) != norm(mt))
print('C. L-chika (AS): %d instructions, %d differ from the assembler/MAME' % (len(recs), bad))
fails += bad
sys.exit(1 if fails else 0)
