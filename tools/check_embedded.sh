#!/usr/bin/env bash
# check_embedded.sh - scripts/night_run.sh, scripts/blockcut_run.sh and scripts/tls_run.sh carry their own copies of the
# benchmark client and tools (so that one file is enough on the test machine). This check fails if an
# embedded copy and the file in the repository differ.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
rc=0
check() {   # $1 = script, $2 = heredoc tag, $3 = file in the repository
  awk -v t="$2" 'f && $0 == t {f=0} f {print} !f && substr($0, length($0) - length(t) - 3) == "<<\047" t "\047" {f=1}' "$1" > "$tmp/x"
  if [ ! -s "$tmp/x" ]; then echo "$1: no embedded copy tagged $2"; rc=1
  elif ! cmp -s "$tmp/x" "$3"; then echo "$3 differs from the copy in $1"; rc=1; fi
}
check scripts/night_run.sh BENCH_NIGHT_EOF bench/bench_night.mjs
check scripts/night_run.sh DECODE_EOF tools/decode_blockfile.py
check scripts/blockcut_run.sh BENCH_NIGHT_EOF bench/bench_night.mjs
check scripts/blockcut_run.sh BLOCK_SIZES_EOF tools/block_sizes.py
check scripts/blockcut_run.sh MITIGATION_EOF tools/mitigation_estimate.py
check scripts/blockcut_run.sh SUMMARIZE_BLOCKCUT_EOF tools/summarize_blockcut.py
check scripts/tls_run.sh TLSPROBE_GO_EOF tools/tlsprobe/main.go
check scripts/tls_run.sh TLSPROBE_MOD_EOF tools/tlsprobe/go.mod
check scripts/tls_run.sh TLS_PROBE_NODE_EOF tools/tls_probe_node.mjs
check scripts/tls_run.sh SUMMARIZE_TLS_EOF tools/summarize_tls.py
rm -rf "$tmp"
[ $rc = 0 ] && echo "embedded copies match"
exit $rc
