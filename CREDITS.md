# Credits

## Upstream

- Source: Ghidra pull request [#5012](https://github.com/NationalSecurityAgency/ghidra/pull/5012),
  "Feature/CPU: Add support for Mitsubishi MELPS-740 (6502 variant)", head commit
  `7279b44f2fa534915cca990f8b2b5cce87d860d4` (branch `philpem-add-melps740`, still open when imported).
- Original author: Philip Pemberton (GitHub `philpem`; commits authored as "Philip Pemberton",
  "philpem" and "Phil"): the MELPS-740 additions to the 6502 module (`melps740.slaspec`,
  `melps740.pspec`, the `MELPS740` language entry), including the instruction set additions
  (BBC/BBS, SEB/CLB, BRA, CLT/SET, COM, JMP/JSR variants, LDM, RRF, TST, FST/SLW/WIT/STP, INC A/DEC A),
  the status bit `T`, and the SFR and vector symbols in the processor spec.
- The 6502 base the pull request builds on is `Ghidra/Processors/6502` from the Ghidra project
  (Apache-2.0, National Security Agency and the Ghidra contributors).
- License: Apache-2.0 (Ghidra contribution). The `LICENSE` file is the Apache-2.0 text shipped with
  Ghidra. Modifications stay under Apache-2.0.

## What Ghidra-Rare changed (see the git history for the exact commits)

- Moved the files into a stand-alone `M740` module (the pull request modified Ghidra's built-in 6502
  module; this module has its own base, its own language definitions and no 6502 languages).
- Rewrote the instruction semantics after checking each instruction against the Series 740 User's
  Manual: the `T` flag now redirects `ADC`, `AND`, `CMP`, `EOR`, `LDA`, `ORA` and `SBC` to the zero-page
  byte at X (the pull request's stated limitation), decimal mode for `ADC`/`SBC`, a zero-page stack
  (stack pointer `S`, page register `SPH`) with the manual's stack layout for `JSR`, `BRK` and `RTI`,
  `RTS`/`RTI` return addresses, zero-page wrap of indexed and indirect zero-page operands, `BRK` pushing the
  address of the BRK plus two, `PLP`/`PHP`/`RTI` with the `T` bit.
- Corrected defects of the 6502 base that the pull request inherited: `ADC` set `V` from the carry,
  `STA #imm` decoded at `89` (the manual defines no such encoding), the stack was in page 1 (the manual puts it in page 0),
  `JSR` pushed the address after the instruction where the hardware pushes the address of its last byte (and `RTS`
  did not add one), the special-page `JSR` called the contents of the page address instead of the address itself,
  pointers fetched from zero page did not wrap within page 0, and `BRK` used the reset vector.
- Added `MUL` (62) and `DIV` (E2) for the M37450 family, `WIT`, and split the family into three languages
  (`default` = FST/SLW with special page 1Fxx, `wit` = WIT with special page FFxx, `muldiv` = WIT + MUL/DIV).
- New `melps740.cspec` (the pull request used the 6502 one), pspec without the 6502 page-1 stack block.
- Added build files (`build.gradle`, `extension.properties`, `Module.manifest`), `README.md`, `GHIDRA-RARE.md`, tests
  (`test/`), the release workflow (added by the Ghidra-Rare maintainers).

## Sources used for the verification (no source code of GPL tools was read)

- Mitsubishi, *Series 740 User's Manual* (1989), Bitsavers copy
  `components/mitsubishi/melps/1989_Series_740_Software_Users_Manual.pdf`: instruction descriptions, opcode matrix,
  stack behaviour, flags. The manual's own text is not redistributed here.
- MAME `unidasm -arch m740` and the AS macro assembler (`asl -cpu MELPS740`), both run as black boxes.
- `mnaberez/m740dasm` (BSD-3-Clause), whose end-to-end test program lists one line per opcode form; used as a
  second, independent opcode table. Only its test assembly file is used, fetched by pinned URL and hash.
- `alpine183/SBC740` (GPL-3.0): the OSI/Microsoft BASIC port for the M50747 and the "L-chika" blinker, fetched by pinned URL
  and hash, never committed here.
