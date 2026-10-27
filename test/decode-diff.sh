#!/usr/bin/env bash
# Decode differential: test/decode-diff.sh <outdir>
# Builds the corpus (every opcode with every operand byte, three-byte forms with 22 high bytes,
# 120,000 random records), decodes it with Ghidra in each language, compares with MAME
# `unidasm -arch m740` (compare.py) and cross-checks with the AS assembler (asl_check.py).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(readlink -m "${1:-${TMPDIR:-/tmp}/m740-decode}")
mkdir -p "$OUT/dec"
head -c 64 /dev/zero > "$OUT/z.bin"
python3 "$HERE/gen_corpus.py" "$OUT/dec" 1
for v in default wit muldiv; do
	"$HERE/ghidra-script.sh" raw "MELPS740:LE:16:$v" "$OUT/z.bin" DumpRecs.java \
		"$OUT/dec/recs.txt" "$OUT/dec/data.bin" "$OUT/dec/g_$v.txt"
	python3 "$HERE/compare.py" "$OUT/dec" "$OUT/dec/g_$v.txt" "$v"
	if command -v "${ASL:-asl}" >/dev/null; then
		mkdir -p "$OUT/asl_$v"
		cp "$OUT/z.bin" "$OUT/asl_$v/z.bin"
		ln -sfn "$OUT/dec" "$OUT/asl_$v/dec"
		cp "$OUT/dec/g_$v.txt" "$OUT/asl_$v/g_$v.txt"
		python3 "$HERE/asl_check.py" "$OUT/asl_$v" "$v" "$HERE/ghidra-script.sh"
	else
		echo "asl not found: AS cross-check skipped"
	fi
done
