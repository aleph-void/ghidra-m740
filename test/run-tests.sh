#!/usr/bin/env bash
# MELPS 740 module test suite.   test/run-tests.sh [--real <workdir>]
# Needs GHIDRA_INSTALL_DIR (a Ghidra with this module under Ghidra/Processors/M740), python3,
# MAME unidasm (ref decoder) and, for the AS cross-check, asl. --real <workdir> also fetches and
# checks the real-code samples (curl; CC65=<cc65 bin dir> for ca65/ld65; P2BIN=<path of p2bin>).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
OUT=${TMPDIR:-/tmp}/m740-tests
mkdir -p "$OUT"
REAL=
[[ ${1:-} == --real ]] && REAL=$2

echo "## 1. specs compile"
for s in "$MOD"/data/languages/*.slaspec; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$s" "$OUT/$(basename "$s" .slaspec).sla" >"$OUT/sleigh.log" 2>&1 \
		|| { tail -20 "$OUT/sleigh.log"; exit 1; }
	echo "  $(basename "$s"): $(stat -c %s "$OUT/$(basename "$s" .slaspec).sla") bytes"
done

echo "## 2. emulator cases (and one deliberately broken expectation per language)"
for v in default wit muldiv; do
	"$HERE/emu-test.sh" "$OUT/emu" "MELPS740:LE:16:$v" | tail -1
	"$HERE/emu-test.sh" --broken "$OUT/emu" "MELPS740:LE:16:$v" | tail -1
done

echo "## 3. every constructor reached"
"$HERE/every-entry.sh" "$OUT/every"

echo "## 4. decode differential (MAME unidasm, AS)"
"$HERE/decode-diff.sh" "$OUT/decode"

if [[ -n $REAL ]]; then
	echo "## 5. real code"
	"$HERE/fetch-samples.sh" "$REAL"
	"$HERE/real-tests.sh" "$REAL"
fi
echo "all tests passed"
