#!/usr/bin/env bash
# Every-entry test: test/every-entry.sh [outdir]. CoverageCheck.java builds instructions from every
# pattern of the SLEIGH decision tree and lists the constructors that no decode reached.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
OUTD=$(readlink -m "${1:-${TMPDIR:-/tmp}/m740-every}")
mkdir -p "$OUTD"
head -c 64 /dev/zero > "$OUTD/z.bin"
rc=0
for v in default wit muldiv; do
	"$HERE/ghidra-script.sh" raw "MELPS740:LE:16:$v" "$OUTD/z.bin" CoverageCheck.java "$OUTD/cov_$v.txt" 64 1
	echo "$v: $(tail -1 "$OUTD/cov_$v.txt")"
	grep -q ' 0 unreached' "$OUTD/cov_$v.txt" || { grep unreached "$OUTD/cov_$v.txt" | head; rc=1; }
done
exit $rc
