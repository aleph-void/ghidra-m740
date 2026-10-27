#!/usr/bin/env bash
# Import a raw image, auto-analyze, and run RealCheck.java (summary, listing, decompilation).
#   test/ghidra-raw.sh <image.bin> <base-hex> <language-id> <outprefix> [decompile-timeout] [fn-address ...]
# Functions are also created at the given addresses (vector targets) before decompiling.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(readlink -f "$1"); BASE=$2; LANG_ID=$3; P=$(readlink -m "$4"); TMO=${5:-60}
shift 5 || shift $#
FN=()
for a in "$@"; do FN+=(-postScript CreateFunction.java "$a"); done
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/raw.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" -loader BinaryLoader \
	-loader-baseAddr "$BASE" -processor "$LANG_ID" -scriptPath "$HERE" \
	"${FN[@]}" -postScript RealCheck.java "$P.summary" "$P.dis" "$P.c" "$TMO" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -30 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $P.summary ]] || { tail -30 "$PROJ/log.txt" >&2; exit 1; }
grep -v "^  Warning\|^  Error" "$P.summary"
