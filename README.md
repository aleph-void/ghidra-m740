# Mitsubishi MELPS 740 (M507xx / "740 series") for Ghidra

SLEIGH processor module for the Mitsubishi (now Renesas) MELPS 740 8-bit core: a 6502 derivative with
bit instructions (`SEB`/`CLB`/`BBS`/`BBC`), `BRA`, `LDM`, `COM`, `RRF`, `TST`, `JMP (zp)`/`JSR (zp)`/special-page
`JSR`, the `T` flag (memory-to-memory arithmetic through X) and a zero-page stack.

Originally written by Philip Pemberton as Ghidra pull request #5012 (a variant of Ghidra's 6502 module);
verified and extended by Ghidra-Rare. See [CREDITS.md](CREDITS.md) for the provenance and
[GHIDRA-RARE.md](GHIDRA-RARE.md) for what is tested, the results and the remaining gaps. Prebuilt zips
for Ghidra 12.1.3, 12.1.4 and 12.2 are on this repository's Releases page.

## Languages

| ID | Instructions that differ |
|---|---|
| `MELPS740:LE:16:default` | M50740A/M50741/M50752/M50757/M50758 group: `FST` (E2), `SLW` (C2); special page `JSR \$nn` goes to 1Fnn |
| `MELPS740:LE:16:wit` | `WIT` (C2); special page FFnn |
| `MELPS740:LE:16:muldiv` | as `wit`, plus `MUL $zz,X` (62) and `DIV $zz,X` (E2) (M37450 type) |

`STP` (42) is common. `FST`/`SLW`/`WIT`/`STP` are pcodeops (they gate the clock). `BRK` uses the vector at FFF4
(INT2's, which the manual says some devices share); other devices use another address.

## Install

Download the zip for your Ghidra version from the Releases page and use File > Install Extensions, or
unpack it into `Ghidra/Extensions`. To build: `GHIDRA_INSTALL_DIR=<ghidra> gradle buildExtension`.

## Stack page

The 740 keeps its stack in zero page (page 1 on devices whose CPU mode register selects it). The module
addresses the stack as `SPH:S`; `SPH` is 0 after reset. For emulation of a program that selects page 1 write
`SPH = 1`. `SPH` is not a tracked value (a constant page makes the decompiler lose stack variables).

## Limitations of the original pull request

| Limitation stated in the PR | State |
|---|---|
| The `T` bit was implemented but ignored by `ADC`, `SBC`, `AND`, `ORA`, `EOR` | Fixed (also `CMP` and `LDA`); tested in the emulator |
| `MUL` and `DIV` not implemented | Fixed in the `muldiv` language |
| `JMP (zp)`, `JSR (zp)` and the special-page `JSR` untested ("TESTME") | Fixed and tested (the special-page `JSR` used the wrong operand) |
| No unit test | `test/run-tests.sh` (emulator cases, decode differential, real code) |

See GHIDRA-RARE.md for the remaining gaps.
