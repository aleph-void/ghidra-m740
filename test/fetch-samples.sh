#!/usr/bin/env bash
# Fetch the real-code samples into <workdir> (never committed): pinned URL + SHA-256.
#   test/fetch-samples.sh <workdir>
# Needs curl, sha256sum, and for the BASIC image cc65's ca65/ld65 (CC65=<cc65 bin dir>, default PATH).
set -euo pipefail
W=$(readlink -m "${1:?workdir}")
mkdir -p "$W"
HERE=$(cd "$(dirname "$0")" && pwd)
get() { # url sha256 file
	if [[ ! -f $W/$3 ]] || ! echo "$2  $W/$3" | sha256sum -c --quiet 2>/dev/null; then
		curl -fsSL -o "$W/$3" "$1"
	fi
	echo "$2  $W/$3" | sha256sum -c --quiet
}
SBC=https://raw.githubusercontent.com/alpine183/SBC740/033f211a20c03dacdccf22321923106f58ae021d
get $SBC/osi_bas.s 01f8ff85052834e7a25c03eea65089d54ea4b9575c51d5e34d25599ca6e9ddaa osi_bas.s
get $SBC/L-chika_for_MELPS740.asm a63643011304f873cdaeb310bed7771f80ac834fc9011d4c3b32f15970bbed45 lchika.asm
get https://raw.githubusercontent.com/mnaberez/m740dasm/b028f404c253dbe2198d1ee138b8802269dffd98/m740dasm/tests/end_to_end/testprog.asm \
	bf904b858db170bb45db59e01335b2b066b00cbf90500c440bfa80fdd59e28ac testprog.asm

# OSI/MS BASIC as ported to the MELPS 740 (SBC740): build with ca65/ld65. Three immediates with a
# negative value need an explicit low-byte operator for the current ca65.
CC=${CC65:-}
[[ -n $CC ]] && CC=$CC/
sed -e '581s/#TEMP1-FAC+1/#<(TEMP1-FAC+1)/' -e '4461s/#-MANTISSA_BYTES/#<(-MANTISSA_BYTES)/' \
	-e '5012s/#-6/#<(-6)/' "$W/osi_bas.s" >"$W/osi2.s"
cat >"$W/osi.cfg" <<'CFG'
MEMORY {
  ZP:    start = $0000, size = $0100, type = rw;
  ROM:   start = $C000, size = $3F00, type = ro, file = %O, fill = yes, fillval = $00;
  IO:    start = $FF00, size = $00FA, type = ro, file = %O, fill = yes, fillval = $00;
  VECTS: start = $FFFA, size = 6, type = ro, file = %O;
}
SEGMENTS {
  ZEROPAGE: load = ZP, type = zp, optional = yes;
  CODE:  load = ROM, type = ro;
  IOHANDLER: load = IO, type = ro;
  VECTS: load = VECTS, type = ro;
}
CFG
"${CC}ca65" --cpu 6502 -l "$W/osi.lst" -o "$W/osi.o" "$W/osi2.s"
"${CC}ld65" -C "$W/osi.cfg" -o "$W/osi.bin" "$W/osi.o"
# the L-chika blinker, assembled with AS (a real MELPS 740 program)
cp "$W/lchika.asm" "$W/lchika_src.asm"
( cd "$W" && "${ASL:-asl}" -q -L -o lchika.p lchika_src.asm && "${P2BIN:-p2bin}" -q lchika.p lchika.bin ) || true
echo "samples ready in $W"
