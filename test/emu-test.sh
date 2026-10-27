#!/usr/bin/env bash
# P-code emulation test: test/emu-test.sh [--broken] [outdir] [language-id]
# Runs every case of test/emu/cases.txt (hand-computed expectations). With --broken it runs a
# copy with one deliberately wrong expectation and succeeds only if exactly that case fails.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
BROKEN=0
[[ ${1:-} == --broken ]] && { BROKEN=1; shift; }
OUTD=$(readlink -m "${1:-${TMPDIR:-/tmp}/m740-emu}")
LANG_ID=${2:-m74000:LE:32:default}
mkdir -p "$OUTD"
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/m740-emu.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
CASES=$HERE/emu/cases.txt
if (( BROKEN )); then
	# the first expectation of the first case is replaced by an impossible value
	awk '/^expect /&&!d{$3="0xdead";d=1}{print}' "$CASES" >"$PROJ/broken.txt"
	CASES=$PROJ/broken.txt
fi
out=$OUTD/emu.txt
(( BROKEN )) && out=$OUTD/emu-broken.txt
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" \
	-loader BinaryLoader -processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript EmuTest.java "$CASES" "$out" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $out ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
grep -v ^PASS "$out"
if (( BROKEN )); then
	first=$(awk '/^case /{print $2; exit}' "$CASES")
	[[ $(grep -c ^FAIL "$out") == 1 ]] && grep -q "^FAIL $first:" "$out" \
		&& echo "broken expectation detected ($first)"
else
	grep -q " 0 failed" "$out"
fi
