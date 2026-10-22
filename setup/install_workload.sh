#!/usr/bin/env bash
# install_workload.sh - copy the chaincode and the benchmark client to the paths scripts/night_run.sh uses
# ($PQC/cityanchor/chaincode and $PQC/cityanchor/bench) and install the client's dependencies.
set -euo pipefail
PQC=${PQC:-$HOME/pqc}
HERE=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$PQC/cityanchor"
cp -r "$HERE/chaincode" "$PQC/cityanchor/"
mkdir -p "$PQC/cityanchor/bench"
cp "$HERE/bench/package.json" "$HERE/bench/bench_night.mjs" "$PQC/cityanchor/bench/"
cd "$PQC/cityanchor/bench" && npm install
node -e "const c=require('crypto');c.generateKeyPairSync('ml-dsa-44');console.log('Node', process.version, 'OpenSSL', process.versions.openssl, ': ML-DSA available')"
