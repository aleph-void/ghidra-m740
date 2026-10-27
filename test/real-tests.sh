#!/usr/bin/env bash
# Real-code tests: test/real-tests.sh <workdir>   (after fetch-samples.sh <workdir>)
# Needs python3, MAME unidasm, asl; the Ghidra analysis step imports the BASIC image raw at C000.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1")
head -c 64 /dev/zero > "$W/z.bin"
echo "-- headless import, auto-analysis and decompilation of the MELPS 740 BASIC image"
"$HERE/ghidra-raw.sh" "$W/osi.bin" c000 MELPS740:LE:16:default "$W/osi" 120 ff00
for v in default wit muldiv; do
	echo "-- instruction checks, language $v"
	python3 "$HERE/real_check.py" "$W" "$HERE/ghidra-script.sh" "$W/osi" "$v"
done
