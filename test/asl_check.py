#!/usr/bin/env python3
"""Cross-check the Ghidra decode against the AS assembler (black box, `asl -cpu MELPS740`).

asl_check.py <workdir> <variant> <ghidra-script-wrapper>

A. asl -> Ghidra: every (mnemonic, operand form) combination is assembled by asl; the bytes of
   every form asl accepts are decoded by Ghidra and the text must agree with the source line.
   The set of opcodes asl accepts is compared with the set Ghidra decodes.
B. Ghidra -> asl: Ghidra's text for ~60,000 corpus records is turned back into assembler source,
   assembled by asl, and the bytes must be the original record.
Exit status 1 on any unexplained difference.
"""
import os, re, subprocess, sys, itertools, collections

work, variant, ghs = sys.argv[1:4]
corp = os.path.join(work, 'dec')
ASL = os.environ.get('ASL', 'asl')
LANG = {'default': 'MELPS740:LE:16:default', 'wit': 'MELPS740:LE:16:wit',
        'muldiv': 'MELPS740:LE:16:muldiv'}[variant]
os.makedirs(work, exist_ok=True)

def assemble(lines, tag):
    """Assemble in small batches: asl 1.42 (build 315) aborts with "stack smashing detected" after
    about 40 reported errors in one run."""
    res = {}
    body = [l for l in lines if not l.strip().startswith('org')]
    for k in range(0, len(body), 24):
        src = os.path.join(work, tag + '.asm')
        open(src, 'w').write('\tcpu melps740\n\torg $1000\n' + '\n'.join(body[k:k + 24]) + '\n')
        subprocess.run([ASL, '-q', '-L', '-o', os.path.join(work, tag + '.p'), src],
                       capture_output=True, text=True)
        for l in open(os.path.join(work, tag + '.lst'), errors='replace'):
            m = re.match(r'^\s*(\d+)/\s*([0-9A-F]+) :\s+((?:[0-9A-F]{2} ?)+)\s+\t(.*)$', l)
            if m:
                res[m.group(4).strip()] = (bytes.fromhex(m.group(3).replace(' ', '')), int(m.group(2), 16))
    return res

def ghidra_decode(recs, tag):
    """recs: list of (bytes, address). returns list of (len, text)"""
    data = b''.join(r for r, a in recs)
    open(os.path.join(work, tag + '.bin'), 'wb').write(data)
    off = 0
    with open(os.path.join(work, tag + '.recs'), 'w') as f:
        for i, (r, a) in enumerate(recs):
            f.write('%d %d %x\n' % (i, off, a))
            off += len(r)
    subprocess.run([ghs, 'raw', LANG, os.path.join(work, 'z.bin'), 'DumpRecs.java',
                    os.path.join(work, tag + '.recs'), os.path.join(work, tag + '.bin'),
                    os.path.join(work, tag + '.out')], check=True)
    out = []
    for l in open(os.path.join(work, tag + '.out')):
        i, n, t = l.rstrip('\n').split(' ', 2)
        out.append((int(n), t))
    return out

def num(m):
    return str(int(m.group(1) or m.group(2), 16))

def norm(t):
    t = t.lower().replace(' ', '')
    t = re.sub(r'\\+0x(?:1f|ff)([0-9a-f]{2})', r'\\$\1', t)
    t = re.sub(r'0x([0-9a-f]+)|\$([0-9a-f]+)', num, t)
    t = re.sub(r'^(seb|clb|bbs|bbc)#', r'\1', t)
    return t

MNS = ('adc and asl bbc bbs bcc bcs beq bit bmi bne bpl bra brk bvc bvs clb clc cld cli clt clv cmp '
       'com cpx cpy dec dex dey div eor fst inc inx iny jmp jsr lda ldm ldx ldy lsr mul nop ora pha '
       'php pla plp rol ror rrf rti rts sbc seb sec sed sei set slw sta stp stx sty tax tay tst tsx '
       'txa txs tya wit').split()
FORMS = ['', 'a', '#$12', '$12', '$12,x', '$12,y', '$1234', '$1234,x', '$1234,y', '($12,x)',
         '($12),y', '($12)', '($1234)', '$1020', '0,a', '1,a', '2,a', '3,a', '4,a', '5,a', '6,a', '7,a',
         '0,$12', '1,$12', '2,$12', '3,$12', '4,$12', '5,$12', '6,$12', '7,$12',
         '0,a,$1020', '1,a,$1020', '2,a,$1020', '3,a,$1020', '4,a,$1020', '5,a,$1020', '6,a,$1020', '7,a,$1020',
         '0,$12,$1020', '1,$12,$1020', '2,$12,$1020', '3,$12,$1020', '4,$12,$1020', '5,$12,$1020', '6,$12,$1020', '7,$12,$1020',
         '#$12,$34', '\\$12', '$12,x']
combos = ['%s %s' % (m, f) if f else m for m in MNS for f in FORMS]

# ---- A: asl -> Ghidra
res = assemble(['\torg $1000'] + ['\t' + c for c in combos], 'combos')
print('A. asl accepts %d of %d (mnemonic, form) combinations' % (len(res), len(combos)))
forms = sorted(res.items())
recs = [(b, a) for s, (b, a) in forms]
dec = ghidra_decode(recs, 'a')
bad = 0
asl_ops = set()
gh_ops = set()
agree = 0
for (src, (b, _a)), (n, t) in zip(forms, dec):
    asl_ops.add(b[0])
    if t == 'BAD':
        # forms asl accepts for other variants: FST/SLW/WIT/MUL/DIV
        mn = src.split()[0]
        ok_bad = (mn == 'fst' and variant != 'default') or (mn == 'slw' and variant != 'default') \
            or (mn == 'wit' and variant == 'default') or (mn in ('mul', 'div') and variant != 'muldiv') \
            or (mn == 'div' and False)
        if mn in ('wit', 'slw', 'fst') and b[0] == 0xC2 and variant == 'default':
            ok_bad = (mn == 'wit')
        if ok_bad:
            continue
        # asl encodes the same opcode for SLW and WIT (C2): only one is valid per variant
        print('  A-UNEXPLAINED: asl assembles %r to %s, Ghidra rejects' % (src, b.hex()))
        bad += 1
        continue
    gh_ops.add(b[0])
    if n != len(b) or norm(t) != norm(src):
        # aliases: asl accepts both slw and wit for C2; fst/slw/wit by variant
        if b[0] == 0xC2 and norm(t) in ('slw', 'wit'):
            agree += 1
            continue
        mn = src.split()[0]
        # asl quirks (see GHIDRA-RARE.md): bare shift/inc/dec mean the accumulator; BRK accepts and
        # ignores an operand; PLP is followed by an inserted NOP; LDA ($zz) assembles to B2 (the
        # 65C02 encoding, which is JMP ($zz) on the 740); DIV/MUL/FST are variant dependent.
        if (norm(src) == mn and norm(t) == mn + 'a') or (mn == 'brk' and norm(t) == 'brk' and len(b) == 2) \
                or (mn == 'plp' and norm(t) == 'plp' and b[:1] == b'\x28') \
                or (src.startswith('lda (') and b[0] == 0xB2 and norm(t).startswith('jmp(')) \
                or (mn in ('div', 'mul') and variant != 'muldiv' and (b[0] in (0x62, 0xE2))) \
                or (mn == 'fst' and variant == 'muldiv'):
            agree += 1
            continue
        print('  A-UNEXPLAINED: %r -> %s -> Ghidra %r' % (src, b.hex(), t))
        bad += 1
    else:
        agree += 1
print('   %d forms agree, %d unexplained; asl opcodes %d' % (agree, bad, len(asl_ops)))

# opcodes Ghidra decodes (from the corpus dump for this variant) vs opcodes asl accepts
gd = {}
gl = {}
for l in open(os.path.join(work, 'g_%s.txt' % variant)):
    i, n, t = l.rstrip('\n').split(' ', 2)
    gd[int(i)] = t
    gl[int(i)] = int(n)
data = open(os.path.join(corp, 'data.bin'), 'rb').read()
rl = [l.split() for l in open(os.path.join(corp, 'recs.txt'))]
for i, r in enumerate(rl):
    if gd[i] != 'BAD':
        gh_ops.add(data[int(r[1])])
only_gh = sorted(gh_ops - asl_ops)
only_asl = sorted(asl_ops - gh_ops)
print('   opcodes Ghidra decodes that asl does not assemble: %s' % ' '.join('%02x' % o for o in only_gh))
print('   opcodes asl assembles that Ghidra rejects: %s' % ' '.join('%02x' % o for o in only_asl))
# FST/SLW/WIT/MUL/DIV exist only in some variants: asl accepts all of them
expected_only_asl = {'default': [0x62], 'wit': [0x62, 0xE2], 'muldiv': []}[variant]
if only_asl != expected_only_asl or only_gh:
    print('  A-UNEXPLAINED opcode set difference')
    bad += 1

# ---- B: Ghidra -> asl
sel = []
for i, r in enumerate(rl):
    op = data[int(r[1])]
    n = int(open(os.path.join(corp, 'lens.txt')).read().split()[op])
    if gd[i] == 'BAD':
        continue
    if n < 3 or i % 8 == 0:
        sel.append(i)
def to_asl(t):
    t = t.lower()
    t = re.sub(r'\\+0x(?:1f|ff)([0-9a-f]{2})', r'\\$\1', t)
    t = re.sub(r'0x([0-9a-f]+)', r'$\1', t)
    t = re.sub(r'^(seb|clb|bbs|bbc) #', r'\1 ', t)
    return t
want = []
srcs = []
REL = ('bcc', 'bcs', 'beq', 'bne', 'bmi', 'bpl', 'bvc', 'bvs', 'bra', 'bbs', 'bbc')
for i in sel:
    n = gl[i]
    want.append(data[int(rl[i][1]):int(rl[i][1]) + n])
srcs = []
BATCH = 150
for k, i in enumerate(sel):
    a = int(rl[i][2], 16)
    a2 = 0x1000 + 8 * (k % BATCH)         # unique address per record within a batch
    t = to_asl(gd[i])
    if t.split()[0] in REL:
        m = re.match(r'^(.*\$)([0-9a-f]{4})$', t)
        t = m.group(1) + '%04x' % ((int(m.group(2), 16) + a2 - a) & 0xffff)
    srcs.append('\torg $%x\n\t%s\n\torg $%x\n\tnop' % (a2, t, a2 + 4))   # the nop resets asl's ADC/SBC tracking
mism = 0
zp_opt = 0
nop_ins = 0
jmpff = 0
for k in range(0, len(sel), BATCH):
    src = os.path.join(work, 'back.asm')
    open(src, 'w').write('\tcpu melps740\n' + '\n'.join(srcs[k:k + BATCH]) + '\n')
    subprocess.run([ASL, '-q', '-L', '-o', os.path.join(work, 'back.p'), src], capture_output=True)
    got = {}
    for l in open(os.path.join(work, 'back.lst'), errors='replace'):
        m = re.match(r'^\s*(\d+)/\s*([0-9A-F]+) :\s*((?:[0-9A-F]{2} ?)*)\s*\t(.*)$', l)
        if m and m.group(3).strip():
            a = int(m.group(2), 16)
            if a not in got:
                got[a] = bytes.fromhex(m.group(3).replace(' ', ''))
    for j in range(min(BATCH, len(sel) - k)):
        w, g, i = want[k + j], got.get(0x1000 + 8 * j), sel[k + j]
        if g == w:
            continue
        if g is not None and g == w + b'\xea':
            nop_ins += 1      # asl appends a NOP after some instructions (PLP, SEC...)
            continue
        if g is not None and len(w) == 3 and len(g) == 2 and w[2] == 0 and not gd[i].startswith('BB') \
                and not gd[i].startswith('LDM'):
            zp_opt += 1      # asl shortens an absolute operand below 0100h to the zero-page form
            continue
        if g is None and w[0] == 0x6C and w[1] == 0xFF:
            jmpff += 1       # asl refuses JMP ($xxFF) (6502 page-wrap guard); the manual has (hhll+1)
            continue
        mism += 1
        if mism <= 20:
            print('  B-UNEXPLAINED: %s ghidra=%r asl=%s want=%s' % (rl[i][2], gd[i], g.hex() if g is not None else None, w.hex()))
print('B. %d Ghidra records re-assembled by asl: %d identical, %d explained (%d asl zero-page form for an absolute operand < 0100h, %d asl-inserted NOP, %d JMP ($xxFF) that asl refuses), %d unexplained' % (len(sel), len(sel) - mism - zp_opt - nop_ins - jmpff, zp_opt + nop_ins + jmpff, zp_opt, nop_ins, jmpff, mism))
sys.exit(1 if bad or mism else 0)
