# Ghidra-Rare notes: Mitsubishi MELPS 740

Based on Ghidra pull request #5012 by Philip Pemberton; provenance, licence and the list of changes are in
[CREDITS.md](CREDITS.md). Targets Ghidra 12.1.3, 12.1.4 and 12.2 (the release zips are built with
`tools/build-module.sh --standard --name M740` from the Ghidra-Rare checkout).

## What it covers

Three languages (`MELPS740:LE:16:default`, `:wit`, `:muldiv`; see README.md). All documented instructions of
the Series 740 manual, including the `T` flag (ADC, SBC, AND, ORA, EOR, CMP, LDA on the zero-page byte at X), decimal mode, zero-page stack,
bit instructions, `MUL`/`DIV` (M37450 family), `FST`/`SLW`/`WIT`/`STP` (pcodeops).

## Testing

`test/run-tests.sh [--real <workdir>]` with `GHIDRA_INSTALL_DIR` set to a Ghidra that has this module under
`Ghidra/Processors/M740`. Needs python3, MAME `unidasm`, `asl` (AS); `--real` also curl and cc65 (`CC65=<bin dir>`),
`P2BIN=<path to p2bin>`.

| Step | Script |
|---|---|
| specs compile | `run-tests.sh` (sleigh) |
| emulator cases | `emu-test.sh` + `emu/cases.txt`, `EmuTest.java` |
| every constructor reached | `every-entry.sh`, `CoverageCheck.java` |
| decode differential (MAME, AS) | `decode-diff.sh`, `gen_corpus.py`, `compare.py`, `asl_check.py`, `DumpRecs.java` |
| real code | `fetch-samples.sh`, `real-tests.sh`, `ghidra-raw.sh`, `real_check.py`, `RealCheck.java` |

## Results

| Area | Result |
|---|---|
| Builds | All three `.slaspec` compile on 12.1.3, 12.1.4 and 12.2; each `.sla` is about 8 KB |
| Decode vs MAME `unidasm -arch m740` | 506,365 records per language (every opcode with every operand byte, three-byte forms with 22 high-byte values, 120,000 random), 0 unexplained. default: 451,998 exact, 53,167 reserved opcodes (MAME decodes the 6502 leftovers `KIL`, `SHX`, `SHY` and the undocumented `NOP` forms), 1,200 FST/SLW that MAME lacks. wit: 451,998 exact, 53,903 reserved. muldiv: 451,998 exact, 52,708 reserved |
| Decode vs AS (`asl -cpu MELPS740`) | asl -> Ghidra: 275/275 (default), 273/273 (wit), 276/276 (muldiv) accepted (mnemonic, operand form) combinations decode to the same text; the opcode sets are identical (231 opcodes in muldiv). Ghidra -> asl: 148,258 / 147,522 / 148,717 records re-assemble to the original bytes; 1,694 explained (asl uses the zero-page form for an absolute operand below 0100h, inserts a NOP after some instructions, refuses `JMP ($xxFF)`); 0 unexplained |
| Second opcode table | the 230 lines of m740dasm's end-to-end test program (one per opcode form, written from the manual) agree on mnemonic and length |
| Every constructor | 115/115 (default), 114/114 (wit), 116/116 (muldiv) |
| Semantics | Emulator 64/64 (default), 64/64 (wit), 66/66 (muldiv), hand-computed from the manual: binary and decimal ADC/SBC with flags, T-flag forms, every addressing mode incl. zero-page wrap, bit instructions, branches, JSR/RTS/BRK/RTI stack contents, PHP/PLP, MUL/DIV, both stack pages; a deliberately broken expectation is detected |
| Real code | OSI/Microsoft BASIC as ported to the M50747 (SBC740, assembled by ca65): 3,667/3,667 assembler-listed instructions identical to the assembler (length, mnemonic) and to MAME in all three languages; headless auto-analysis finds 109 functions (vector target created), 2,569 instructions, 108/108 decompile with 0 failures; every instruction Ghidra made starts at an assembler instruction boundary except 8 that start on a hand-encoded `.byte` (BIT-skip tricks, `CLT`); 21 bad-instruction bookmarks, all explained (15 calls into zero page where the program copies CHRGET at run time, 6 BIT-skip overlaps). L-chika blinker assembled with AS: 18/18 |

## Doesn't work

| Gap | Why |
|---|---|
| `FST`, `SLW`, `WIT`, `STP` are pcodeops | Clock and power state of the device; no p-code can express them |
| Interrupts, timers, ports, serial I/O | Peripheral hardware; the pspec only names generic SFR addresses (device specific, not checked against a datasheet) |
| The BRK vector is FFF4 | Device dependent (FFDE on other families); the manual says only "BADRS" |
| Reset/BRK vector targets are disassembled through the vector pointers but not made functions | Ghidra's pspec entry mechanism; create the function |
| The stack wraps through the 16-bit `SP` instead of within the page | Deliberate: a wrapping 8-bit stack pointer makes the decompiler lose the stack variables. Only matters for a stack overflowing its page |
| `SPH` (stack page) is not set from the device's CPU mode register | Register write to a device-specific peripheral register |
| No ELF opinion, DWARF map or relocations | No compiler or linker emits ELF/DWARF for the 740 |

## Unverified

- Decimal-mode N, V and Z flags: the manual defines C and the accumulator result; N and Z are taken from the
  adjusted result and V from the binary sum.
- `DIV` with A = 0 is modelled as no operation (the manual says the instruction cannot detect it).
- Pointer wrap in zero page for `(zz,X)`, `(zz),Y`, `JMP (zz)`, `JSR (zz)` at zz = FF: assumed to follow the 6502.
- The `B` flag: modelled as set by `BRK` (live and in the pushed copy), as the manual says.
- MUL/DIV and the FST/SLW/WIT groups were checked against the manual and AS only; no hardware.
- SFR names in the pspec come from the pull request.

## Confirmed reference-tool behaviour

- MAME `m740` has no `FST`, `SLW`, `MUL` or `DIV` (E2 decodes as `NOP #imm`, 62 as `KIL`; C2 is `WIT` only), and decodes the 6502
  undocumented opcodes (`KIL`, `SHX`, `SHY`, multi-byte `NOP`) that the Series 740 manual does not define.
- AS 1.42 (build 315) `MELPS740`: `LDA ($zz)` assembles to B2 (the 65C02 encoding, which is `JMP ($zz)` on the 740); `BRK` accepts
  and ignores an operand; a NOP is inserted after `PLP` and between some flag instructions; `JMP ($xxFF)` is refused (the manual defines `(hhll+1)`);
  FST/SLW/WIT/MUL/DIV are accepted for every device; the assembler aborts with "stack smashing detected" after about 40
  reported errors in one run.
