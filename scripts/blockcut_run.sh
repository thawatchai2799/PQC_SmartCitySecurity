#!/usr/bin/env bash
# blockcut_run.sh - block cutting and identity-size experiment on the post-quantum Fabric fork.
#
# Phase 1 (identity size, about 15 min): one run per condition at the default block cutting, with
#   the CLI invoke and 2,000 alerts at 20 clients. The raw block files of that ledger are rebuilt with
#   identities stored as DER or as 32-byte references (tools/mitigation_estimate.py) and compressed,
#   then deleted; only the JSON results are kept.
# Phase 2 (block cutting): every cell <condition>:<setting> is run REPS times in a new random order
#   per repetition, each on a fresh network, with the baseline protocol (1 CLI invoke, then 2,000
#   alerts at 20, 50 and 10 clients). Settings of the orderer (configtx.yaml, Orderer section):
#     pmb512k_bt2s     PreferredMaxBytes 512 KB, BatchTimeout 2s     (the default; control)
#     pmb1m_bt2s       PreferredMaxBytes 1 MB,   BatchTimeout 2s     (block size scaled up)
#     pmb512k_bt500ms  PreferredMaxBytes 512 KB, BatchTimeout 500ms  (shorter timeout)
#   MaxMessageCount stays 10. The channel's genesis block is inspected after every network start to
#   confirm the values in force. The ledger height is read before and after every benchmark, and the
#   block files are scanned (tools/block_sizes.py) so that each benchmark's blocks can be counted.
#
# Start (inside WSL, keep the terminal window open):
#   DL=/path/to/a/folder setsid nohup bash ~/pqc/blockcut_run.sh > ~/pqc/blockcut_console.log 2>&1 &
#   (DL is optional: when set, the packed results are also copied there)
#   sleep 30; tail -f ~/pqc/results/blockcut_*/progress.log    # Ctrl+C stops only the tail, not the run
#   Progress at any time:  cat ~/pqc/blockcut_status.txt
# Stop early:   touch ~/pqc/STOP_BLOCKCUT     (finishes the current run, then packs the results)
#
# Tunables (environment): HOURS=6  REPS=10  RAW_CONDS="ecdsa mldsa44 mldsa65 mldsa87 hybrid44"
#   CELLS="mldsa87:pmb512k_bt2s mldsa87:pmb1m_bt2s mldsa87:pmb512k_bt500ms mldsa44:pmb512k_bt2s mldsa44:pmb1m_bt2s mldsa44:pmb512k_bt500ms"
#   RAW_CONDS="" skips phase 1; REPS=0 skips phase 2.
# It never touches other Fabric networks: everything runs under compose project "pqcnet" in ~/pqc.
# no 'set -u': fabric-samples' envVar.sh reads unset variables (e.g. OVERRIDE_ORG)
HOURS=${HOURS:-6}; REPS=${REPS:-10}
RAW_CONDS=${RAW_CONDS-"ecdsa mldsa44 mldsa65 mldsa87 hybrid44"}
CELLS=${CELLS:-"mldsa87:pmb512k_bt2s mldsa87:pmb1m_bt2s mldsa87:pmb512k_bt500ms mldsa44:pmb512k_bt2s mldsa44:pmb1m_bt2s mldsa44:pmb512k_bt500ms"}
N=2000; MAIN_CONCS="20 50 10"; RAW_CONCS="20"
TN=~/pqc/fabric-samples/test-network; BENCH=~/pqc/cityanchor/bench; CFG=$TN/configtx/configtx.yaml
DL=${DL:-}
OUT=~/pqc/results/blockcut_$(date +%Y%m%d_%H%M); mkdir -p "$OUT/tools"
LOG=$OUT/progress.log; CSV=$OUT/summary.csv; STATUS=~/pqc/blockcut_status.txt
export COMPOSE_PROJECT_NAME=pqcnet PATH=~/pqc/bin:$PATH
START=$(date +%s); END=$(awk -v h="$HOURS" -v n="$START" 'BEGIN{printf "%d", n + h*3600}')
rm -f ~/pqc/STOP_BLOCKCUT
MODIFIED=0     # set to 1 once configtx.yaml or the CA files have been edited; the exit trap then restores them

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
# Long steps run in the background and are waited for, so that a TERM/INT/HUP is handled at once
# (bash defers traps while a foreground command runs); the exit trap then stops CHILD.
CHILD=""
bgwait() { "$@" & CHILD=$!; wait "$CHILD"; local rc=$?; CHILD=""; return $rc; }

# ---------------------------------------------------------------- progress / ETA
DONE_RUNS=0; RUN_SECS=0; AVG_GUESS=240; PLANNED=0
hm() { local s=$1; [ "$s" -lt 0 ] && s=0; printf '%dh %02dm' $((s/3600)) $(((s%3600)/60)); }
progress() {   # $1 = what is happening now
  local now=$(date +%s) avg remain pct left eta note=""
  if [ "$DONE_RUNS" -gt 0 ]; then avg=$(( RUN_SECS / DONE_RUNS )); else avg=$AVG_GUESS; fi
  remain=$(( PLANNED - DONE_RUNS )); [ "$remain" -lt 0 ] && remain=0
  pct=100; [ "$PLANNED" -gt 0 ] && pct=$(( 100 * DONE_RUNS / PLANNED ))
  left=$(( remain * avg + 90 )); eta=$(( now + left ))
  if [ "$eta" -gt "$END" ]; then eta=$END; left=$(( END - now )); note=" - the ${HOURS} h limit will be reached before all runs finish"; fi
  local line="progress ${pct}% (${DONE_RUNS}/${PLANNED} runs) | elapsed $(hm $((now-START))) | remaining ~$(hm $left) | expected finish $(date -d @$eta '+%H:%M (%d/%m)')${note} | avg $((avg/60))m $((avg%60))s per run | now: $1"
  log "$line"
  { echo "last update $(date '+%F %T')"; echo "$line"; echo "results in $OUT"; } > "$STATUS"
}

# ---------------------------------------------------------------- embedded helper files
cat > "$BENCH/bench_night.mjs" <<'BENCH_NIGHT_EOF'
// Benchmark AnchorAlert throughput / latency against the Fabric test-network.
// Usage: node bench.mjs <n_tx> <concurrency>      (default 2000 20)
// Prints JSON: tx_per_s, latency mean/p95/p99 ms, storage of ledger dir (run du separately).
import * as grpc from '@grpc/grpc-js';
import { connect, hash, signers } from '@hyperledger/fabric-gateway';
import * as crypto from 'crypto'; import { promises as fs } from 'fs'; import * as path from 'path';

const N = Number(process.argv[2] || 2000), CONC = Number(process.argv[3] || 20);
const CH = 'mychannel', CC = 'cityanchor';
const ROOT = process.env.FABRIC_SAMPLES || path.resolve(process.env.HOME, 'fabric-samples');
const ORG = path.join(ROOT, 'test-network/organizations/peerOrganizations/org1.example.com');
const certPath = path.join(ORG, 'users/User1@org1.example.com/msp/signcerts');
const keyPath  = path.join(ORG, 'users/User1@org1.example.com/msp/keystore');
const tls = await fs.readFile(path.join(ORG, 'peers/peer0.org1.example.com/tls/ca.crt'));
const client = new grpc.Client('localhost:7051', grpc.credentials.createSsl(tls), { 'grpc.ssl_target_name_override': 'peer0.org1.example.com' });
const cert = await fs.readFile(path.join(certPath, (await fs.readdir(certPath))[0]));
// Night-run change 1: load every key in the keystore; a hybrid identity has two (ECDSA + ML-DSA)
// and signs with the ML-DSA one, so prefer it. A single-key keystore behaves as before.
const keys = [];
for (const f of (await fs.readdir(keyPath)).sort()) {
  try { keys.push(crypto.createPrivateKey(await fs.readFile(path.join(keyPath, f)))); }
  catch (e) { console.error('skip key', f, e.message); }
}
const key = keys.find(k => k.asymmetricKeyType.startsWith('ml-dsa')) ?? keys[0];
const KEY_TYPE = key.asymmetricKeyType;
console.error('client key:', KEY_TYPE, '(keys in keystore:', keys.map(k => k.asymmetricKeyType).join(','), ')');
const gw = connect({
  client,
  identity: { mspId: 'Org1MSP', credentials: cert },
  // Night-run change 2: ML-DSA signs the whole message (the fork does not hash first), so hash.none
  ...(KEY_TYPE.startsWith('ml-dsa') ? { signer: async (m) => crypto.sign(null, m, key), hash: hash.none }
                                    : { signer: signers.newPrivateKeySigner(key) }),
  evaluateOptions: () => ({ deadline: Date.now() + 60000 }),
  endorseOptions: () => ({ deadline: Date.now() + 60000 }),
  submitOptions: () => ({ deadline: Date.now() + 60000 }),
  commitStatusOptions: () => ({ deadline: Date.now() + 120000 }),
});
const contract = gw.getNetwork(CH).getContract(CC);

const lat = []; let done = 0; const t0 = performance.now();
async function worker(w) {
  for (let i = w; i < N; i += CONC) {
    const id = `alert-${Date.now()}-${i}`; const h = crypto.createHash('sha256').update(String(i)).digest('hex');
    const s = performance.now();
    await contract.submitTransaction('AnchorAlert', id, 'Transport', 'dt8', h, String(Date.now()));
    lat.push(performance.now() - s); done++;
  }
}
let failed = 0;
async function safeWorker(w) { try { await worker(w); } catch (e) { failed++; console.error('worker', w, e.message); } }
await Promise.all([...Array(CONC).keys()].map(safeWorker));
const wall = (performance.now() - t0) / 1000; lat.sort((a, b) => a - b);
const q = p => lat[Math.floor(p * (lat.length - 1))];
const out = { cond: process.env.COND || '', rep: process.env.REP || '', key_type: KEY_TYPE, n_tx: done, failed_workers: failed, concurrency: CONC, wall_s: wall, tx_per_s: done / wall,
  latency_ms: { mean: lat.reduce((a, b) => a + b, 0) / lat.length, p50: q(.5), p95: q(.95), p99: q(.99) } };
console.log(JSON.stringify(out, null, 2));
// Night-run change 3: write where the driver says
await fs.writeFile(process.env.OUT_JSON || `bench_result_conc${CONC}.json`, JSON.stringify(out, null, 2));
gw.close(); client.close();
BENCH_NIGHT_EOF
cat > "$OUT/tools/block_sizes.py" <<'BLOCK_SIZES_EOF'
#!/usr/bin/env python3
"""Per-block transaction counts and sizes of Hyperledger Fabric peer block files.

Usage: python3 block_sizes.py blockfile_000000 [blockfile_000001 ...] --json out.json

The peer stores each block as [varint length][serialized block] (see decode_blockfile.py for the
layout). For every block this tool records its number, the number of envelopes it holds, how many of
them are configuration envelopes, and its size in bytes. The output is
  {"files": [...], "blocks": [[number, envelopes, config_envelopes, bytes], ...]}
sorted by block number. A benchmark that ran between heights h0 and h1 (as reported by
`peer channel getinfo`) wrote the blocks numbered h0 .. h1-1.
"""
import json
import sys


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; r |= (c & 0x7F) << s; i += 1
        if not c & 0x80:
            return r, i
        s += 7


def fields(b):
    i, n = 0, len(b)
    while i < n:
        key, i = varint(b, i); f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            ln, i = varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1:
            v = b[i:i + 8]; i += 8
        elif wt == 5:
            v = b[i:i + 4]; i += 4
        else:
            raise ValueError(f"wire type {wt}")
        yield f, wt, v


def is_config(env):
    """True unless ChannelHeader.type is 3 (ENDORSER_TRANSACTION)."""
    for f, wt, payload in fields(env):
        if f == 1 and wt == 2:
            for pf, pwt, header in fields(payload):
                if pf == 1 and pwt == 2:
                    for hf, hwt, chdr in fields(header):
                        if hf == 1 and hwt == 2:
                            for cf, cwt, cv in fields(chdr):
                                if cf == 1 and cwt == 0:
                                    return cv != 3
    return True


def blocks_of(path):
    b = open(path, "rb").read(); i = 0
    while i < len(b):
        ln, j = varint(b, i); blk = b[j:j + ln]; i = j + ln
        k = 0
        number, k = varint(blk, k)
        h, k = varint(blk, k); k += h                 # DataHash
        h, k = varint(blk, k); k += h                 # PreviousHash
        ntx, k = varint(blk, k); ncfg = 0
        for _ in range(ntx):
            el, k = varint(blk, k); ncfg += is_config(blk[k:k + el]); k += el
        yield [number, ntx, ncfg, len(blk)]


def main(paths, out):
    rows = sorted((r for p in paths for r in blocks_of(p)), key=lambda r: r[0])
    nums = [r[0] for r in rows]
    gaps = [n for a, n in zip(nums, nums[1:]) if n != a + 1]
    res = {"files": paths, "blocks": rows, "first": nums[0] if nums else None,
           "last": nums[-1] if nums else None, "gaps": gaps}
    json.dump(res, open(out, "w"))
    print(f"{len(rows)} blocks ({res['first']}..{res['last']}), {sum(r[1] - r[2] for r in rows)} endorser "
          f"transactions, {sum(r[2] for r in rows)} config envelopes, gaps: {gaps or 'none'}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if "--json" not in a or a.index("--json") == len(a) - 1:
        sys.exit(__doc__)
    out = a[a.index("--json") + 1]
    main([x for x in a if x not in ("--json", out)], out)
BLOCK_SIZES_EOF
cat > "$OUT/tools/mitigation_estimate.py" <<'MITIGATION_EOF'
#!/usr/bin/env python3
"""Estimate how much smaller a Fabric block file would be if identities were stored more compactly.

Usage: python3 mitigation_estimate.py blockfile_000000 [more block files of the same ledger] --json out.json

Fabric stores every identity as a SerializedIdentity{1 mspid, 2 id_bytes}, where id_bytes is the
X.509 certificate as PEM text. Identities appear in each transaction (the client in the payload
header and again in the action header, and one per endorsement) and in the orderer signature of
every block's metadata. This tool rebuilds the block file with id_bytes replaced by

  der  the DER encoding of the same certificate (the base64 body of the PEM, decoded)
  ref  a 32-byte reference (SHA-256 of the DER certificate), as if identities already known to the
       channel were referred to instead of embedded

re-encoding every enclosing protobuf message and length prefix, and reports the size of the
result. Nothing else is changed: signatures, hashes and configuration blocks keep their sizes, and
the rebuilt files are counterfactual (their signatures would not verify). Rebuilding with the
certificates unchanged must reproduce the file byte for byte; the tool checks this. Bytes per
transaction are given without the configuration-only blocks (in every variant), and compression is
measured on the file without them.

It also measures general-purpose compression of the original file (gzip level 6 and xz preset 6
from the Python standard library, and zstd level 3 when the zstd command is installed), as a
storage layer with compression would see it.
"""
import base64
import gzip
import hashlib
import json
import lzma
import shutil
import subprocess
import sys


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; r |= (c & 0x7F) << s; i += 1
        if not c & 0x80:
            return r, i
        s += 7


def enc_varint(n):
    out = bytearray()
    while True:
        c = n & 0x7F; n >>= 7
        if n:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


def raw_fields(b):
    """Yield (field_no, wire_type, raw_bytes_of_whole_field, value_bytes_or_None)."""
    i, n = 0, len(b)
    while i < n:
        start = i; key, i = varint(b, i); f, wt = key >> 3, key & 7
        if wt == 0:
            _, i = varint(b, i); v = None
        elif wt == 2:
            ln, i = varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1:
            i += 8; v = None
        elif wt == 5:
            i += 4; v = None
        else:
            raise ValueError(f"wire type {wt}")
        if i > n:
            raise ValueError("truncated field")
        yield f, wt, b[start:i], v


# Schemas: field number -> schema of the embedded message, or "ID" for SerializedIdentity.id_bytes.
SERIALIZED_IDENTITY = {2: "ID"}
SIGNATURE_HEADER = {1: SERIALIZED_IDENTITY}
HEADER = {2: SIGNATURE_HEADER}
ENDORSEMENT = {1: SERIALIZED_IDENTITY}
ENDORSED_ACTION = {2: ENDORSEMENT}
CC_ACTION_PAYLOAD = {2: ENDORSED_ACTION}
TX_ACTION = {1: SIGNATURE_HEADER, 2: CC_ACTION_PAYLOAD}
TRANSACTION = {1: TX_ACTION}
PAYLOAD = {1: HEADER, 2: TRANSACTION}
ENVELOPE = {1: PAYLOAD}
METADATA_SIGNATURE = {1: SIGNATURE_HEADER}
METADATA = {2: METADATA_SIGNATURE}


class Rewriter:
    def __init__(self, mode):
        self.mode = mode; self.rewritten = 0; self.where = None; self.counts = {"transactions": 0, "block_metadata": 0}

    def ident(self, idb):
        if not idb.startswith(b"-----BEGIN"):
            return idb
        self.rewritten += 1; self.counts[self.where] += 1
        if self.mode == "pem":
            return idb
        lines = [l for l in idb.decode("ascii").splitlines() if l and not l.startswith("-----")]
        der = base64.b64decode("".join(lines))
        return der if self.mode == "der" else hashlib.sha256(der).digest()

    def msg(self, b, schema):
        out = bytearray()
        for f, wt, raw, v in raw_fields(b):
            sub = schema.get(f) if wt == 2 else None
            if sub is None:
                out += raw; continue
            nv = self.ident(v) if sub == "ID" else self.msg(v, sub)
            if nv is v or nv == v:
                out += raw
            else:
                out += enc_varint((f << 3) | 2) + enc_varint(len(nv)) + nv
        return bytes(out)


def is_endorser_tx(env):
    for f, wt, raw, payload in raw_fields(env):
        if f == 1 and wt == 2:
            for pf, pwt, praw, header in raw_fields(payload):
                if pf == 1 and pwt == 2:
                    for hf, hwt, hraw, chdr in raw_fields(header):
                        if hf == 1 and hwt == 2:
                            for cf, cwt, craw, cv in raw_fields(chdr):
                                if cf == 1 and cwt == 0:
                                    return varint(craw, 1)[0] == 3
    return False


def rebuild(data, rw):
    """Rebuild a whole block file. Returns (bytes, endorser transactions, blocks, bytes of the
    configuration-only blocks in the result, original records of the other blocks)."""
    out = bytearray(); i = 0; ntx_total = 0; nblk = 0; cfg_bytes = 0; data_records = bytearray()
    while i < len(data):
        rec_start = i
        ln, j = varint(data, i); blk = data[j:j + ln]; i = j + ln; nblk += 1; block_endorser = 0
        k = 0; nb = bytearray()
        _, k2 = varint(blk, k); nb += blk[k:k2]; k = k2                      # block number
        for _ in range(2):                                                   # DataHash, PreviousHash
            h, k2 = varint(blk, k); nb += blk[k:k2 + h]; k = k2 + h
        ntx, k2 = varint(blk, k); nb += blk[k:k2]; k = k2
        for _ in range(ntx):
            el, k2 = varint(blk, k); env = blk[k2:k2 + el]; k = k2 + el
            if is_endorser_tx(env):
                ntx_total += 1; block_endorser += 1; rw.where = "transactions"; env = rw.msg(env, ENVELOPE)
            nb += enc_varint(len(env)) + env
        nmeta, k2 = varint(blk, k); nb += blk[k:k2]; k = k2
        for m in range(nmeta):
            el, k2 = varint(blk, k); item = blk[k2:k2 + el]; k = k2 + el
            if m == 0 and item:                                              # SIGNATURES metadata
                rw.where = "block_metadata"; item = rw.msg(item, METADATA)
            nb += enc_varint(len(item)) + item
        assert k == len(blk), "block not fully consumed"
        rec = enc_varint(len(nb)) + nb
        out += rec
        if block_endorser == 0:
            cfg_bytes += len(rec)
        else:
            data_records += data[rec_start:i]
    return bytes(out), ntx_total, nblk, cfg_bytes, bytes(data_records)


def main(paths, out_json):
    data = b"".join(open(p, "rb").read() for p in paths)
    res = {"files": paths, "file_bytes": len(data)}
    same, ntx, nblk, cfg, records = rebuild(data, Rewriter("pem"))
    assert same == data, "rebuilding with unchanged identities did not reproduce the file"
    assert len(records) + cfg == len(data)
    # Bytes per transaction leave out the configuration-only blocks (genesis and channel updates), in every
    # variant; "with_config_per_tx" keeps them, as in a whole-file average.
    base = len(data) - cfg
    res.update(transactions=ntx, blocks=nblk, config_block_bytes=cfg,
               identity_check="rebuild reproduces the file byte for byte")
    res["pem"] = {"file_bytes": base, "per_tx": base / ntx, "with_config_per_tx": len(data) / ntx}
    for mode in ("der", "ref"):
        rw = Rewriter(mode)
        b, _, _, cfg2, _ = rebuild(data, rw)
        nb = len(b) - cfg2
        res[mode] = {"file_bytes": nb, "per_tx": nb / ntx, "saving_pct": 100 * (1 - nb / base),
                     "identities_rewritten": rw.counts,
                     "identities_per_tx": rw.counts["transactions"] / ntx}
    comp = {"gzip6": len(gzip.compress(records, 6)), "xz6": len(lzma.compress(records, preset=6))}
    if shutil.which("zstd"):
        comp["zstd3"] = len(subprocess.run(["zstd", "-3", "-c", "-q"], input=records, capture_output=True, check=True).stdout)
    for k, v in comp.items():
        res[k] = {"file_bytes": v, "per_tx": v / ntx, "saving_pct": 100 * (1 - v / base)}
    json.dump(res, open(out_json, "w"), indent=1)
    print(f"{ntx} transactions in {nblk} blocks, {len(data)} B; without configuration blocks {base / ntx:.0f} B/tx")
    for k in ("der", "ref", "gzip6", "xz6", "zstd3"):
        if k in res:
            print(f"  {k:6s} {res[k]['per_tx']:9.0f} B/tx  saving {res[k]['saving_pct']:5.1f}%")


if __name__ == "__main__":
    a = sys.argv[1:]
    if "--json" not in a or a.index("--json") == len(a) - 1:
        sys.exit(__doc__)
    out = a[a.index("--json") + 1]
    main([x for x in a if x not in ("--json", out)], out)
MITIGATION_EOF
cat > "$OUT/tools/summarize_blockcut.py" <<'SUMMARIZE_BLOCKCUT_EOF'
#!/usr/bin/env python3
"""Summary tables from one results directory written by scripts/blockcut_run.sh.

Usage: python3 tools/summarize_blockcut.py results/blockcut_YYYYMMDD_HHMM [--json out.json]

Block cutting (phase 2): for every condition, orderer setting and concurrency, the mean and 95%
confidence interval (t distribution) over repetitions of throughput, mean latency and 99th-percentile
latency, and, from the scanned block files, the transactions per block of that benchmark's blocks
(blocks numbered height_before .. height_after-1) and the share of those blocks holding fewer than
MaxMessageCount (10) transactions. Benchmarks in which a client worker failed are excluded and listed.

Identity size (phase 1): block-file bytes per transaction as stored (PEM), rebuilt with identities
as DER or as 32-byte references, and compressed (see tools/mitigation_estimate.py).
"""
import csv
import json
import math
import os
import statistics as st
import sys

T95 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262,
       11: 2.228, 12: 2.201, 13: 2.179, 14: 2.160, 15: 2.145, 16: 2.131, 17: 2.120, 18: 2.110, 19: 2.101,
       20: 2.093, 21: 2.086, 22: 2.080, 23: 2.074, 24: 2.069, 25: 2.064, 26: 2.060, 27: 2.056, 28: 2.052,
       29: 2.048, 30: 2.045}
CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]
SETTINGS = ["pmb512k_bt2s", "pmb1m_bt2s", "pmb512k_bt500ms"]
MAX_MSG = 10


def mci(v):
    v = [x for x in v if x is not None and not math.isnan(x)]
    if not v:
        return float("nan"), float("nan"), 0
    m = st.mean(v)
    if len(v) < 2:
        return m, float("nan"), len(v)
    return m, T95.get(len(v), 1.96) * st.stdev(v) / math.sqrt(len(v)), len(v)


RUN_ORDER = ["20", "50", "10"]   # concurrencies in the order blockcut_run.sh runs them
SETUP_TX = 4          # chaincode lifecycle (2 approvals, 1 commit) and the CLI invoke, before the benchmarks


def stats_of(rows):
    tx = [r[1] - r[2] for r in rows]
    return {"blocks": len(rows), "tx": sum(tx), "tx_per_block": sum(tx) / len(rows),
            "short_share": sum(1 for t in tx if t < MAX_MSG) / len(rows), "max_block_bytes": max(r[3] for r in rows)}


def ranges_by_count(blocks, run_rows):
    """Fallback when heights were not read: assign blocks to the run's benchmarks in the order they ran,
    by counting endorser transactions after the set-up transactions. Only used when every benchmark of
    the run committed its full count and every boundary falls between blocks; otherwise None."""
    data = [r for r in blocks if r[1] - r[2] > 0]
    out, i, seen = {}, 0, 0
    while i < len(data) and seen < SETUP_TX:
        seen += data[i][1] - data[i][2]; i += 1
    if seen != SETUP_TX:
        return None
    for r in run_rows:
        want, got, start = int(r["n_tx"]), 0, i
        while i < len(data) and got < want:
            got += data[i][1] - data[i][2]; i += 1
        if got != want:
            return None
        out[r["concurrency"]] = data[start:i]
    return out


def block_stats(run_dir, row, run_rows):
    """Block statistics of one benchmark: from heights h0 .. h1-1 when they were read and agree with the
    committed count, else from the transaction-count fallback. Returns (stats or None, source)."""
    p = os.path.join(run_dir, "blocks.json")
    if not os.path.exists(p):
        return None, "no blocks.json"
    blocks = json.load(open(p))["blocks"]
    h0, h1 = row.get("height_before", ""), row.get("height_after", "")
    if h0.isdigit() and h1.isdigit():
        rows = [r for r in blocks if int(h0) <= r[0] < int(h1)]
        if rows and len(rows) == int(h1) - int(h0) and sum(r[1] - r[2] for r in rows) == int(row["n_tx"]):
            return stats_of(rows), "heights"
    ordered = [r for r in run_rows if r["phase"] == "main"]
    # only when the run has one complete row per benchmark, in the driver's order (20, 50, 10 clients):
    # a benchmark that left no row may still have committed transactions
    if [r["concurrency"] for r in ordered] == RUN_ORDER and \
            all(r["failed_workers"] == "0" and int(r["n_tx"]) > 0 for r in ordered):
        rng = ranges_by_count(blocks, ordered)
        if rng and rng.get(row["concurrency"]):
            return stats_of(rng[row["concurrency"]]), "count"
    return None, "unresolved"


def fmt(m, ci, d=1):
    return f"{m:.{d}f} ± {ci:.{d}f}" if not math.isnan(ci) else (f"{m:.{d}f}" if not math.isnan(m) else "-")


def main(d, out_json=None):
    rows = list(csv.DictReader(open(os.path.join(d, "summary.csv"))))
    res = {"excluded": [], "blockcut": {}, "identity_size": {}}

    # ------------------------------------------------ phase 2
    main_rows = [r for r in rows if r["phase"] == "main"]
    bad = [r for r in main_rows if int(r["n_tx"]) <= 0 or r["failed_workers"] != "0"]
    res["excluded"] = bad
    ok = [r for r in main_rows if r not in bad]
    print(f"block cutting: {len(main_rows)} benchmarks, excluded {len(bad)}")
    for r in bad:
        print("  excluded:", r["cond"], r["setting"], "rep", r["rep"], "c", r["concurrency"], "n_tx", r["n_tx"])
    missing_blocks = 0; sources = {}
    concs = sorted({int(r["concurrency"]) for r in main_rows})
    for cond in CONDS:
        for c in concs:
            base = None
            for s in SETTINGS:
                sel = [r for r in ok if r["cond"] == cond and r["setting"] == s and int(r["concurrency"]) == c]
                if not sel:
                    continue
                bs = []
                for r in sel:
                    run_rows = [x for x in main_rows if x["cond"] == cond and x["setting"] == s and x["rep"] == r["rep"]]
                    b, src = block_stats(os.path.join(d, cond, s, "rep" + r["rep"]), r, run_rows)
                    sources[src] = sources.get(src, 0) + 1
                    if b:
                        bs.append(b)
                    else:
                        missing_blocks += 1
                o = {"tx_per_s": mci([float(r["tx_per_s"]) for r in sel]),
                     "mean_ms": mci([float(r["mean_ms"]) for r in sel]),
                     "p99_ms": mci([float(r["p99_ms"]) for r in sel]),
                     "tx_per_block": mci([b["tx_per_block"] for b in bs]),
                     "short_block_share": mci([b["short_share"] for b in bs]),
                     "max_block_bytes": max((b["max_block_bytes"] for b in bs), default=None),
                     "runs_with_block_counts": len(bs)}
                res["blockcut"][f"{cond}|{s}|c{c}"] = o
                if s == SETTINGS[0]:
                    base = o
    print("\nmean ± 95% CI over repetitions; tx/block and short blocks (< 10 tx) from the benchmark's own blocks")
    print(f"{'condition':9s} {'setting':16s} {'clients':>7s} {'n':>3s} {'tx/s':>15s} {'mean ms':>15s} {'p99 ms':>17s}"
          f" {'tx/block':>13s} {'short blocks':>13s} {'max block':>10s}")
    for k, o in res["blockcut"].items():
        cond, s, c = k.split("|")
        print(f"{cond:9s} {s:16s} {c[1:]:>7s} {o['tx_per_s'][2]:3d} {fmt(*o['tx_per_s'][:2]):>15s} "
              f"{fmt(*o['mean_ms'][:2]):>15s} {fmt(*o['p99_ms'][:2], d=0):>17s} {fmt(*o['tx_per_block'][:2], d=2):>13s} "
              f"{fmt(o['short_block_share'][0] * 100, o['short_block_share'][1] * 100, d=0) + '%':>13s} "
              f"{(str(o['max_block_bytes']) if o['max_block_bytes'] else '-'):>10s}")
    print("block counts taken from: " + ", ".join(f"{k} {v}" for k, v in sorted(sources.items())))
    if missing_blocks:
        print(f"note: {missing_blocks} benchmarks had no usable block counts")

    # ------------------------------------------------ phase 1
    print("\nidentity size: block-file bytes per endorser transaction (one ledger per condition: set-up, CLI invoke and 2,000 alerts at 20 clients; configuration blocks left out)")
    print(f"{'condition':9s} {'tx':>5s} {'PEM (stored)':>13s} {'DER':>16s} {'reference':>16s} {'gzip -6':>16s} {'xz -6':>16s} {'zstd -3':>16s}")
    base_pem = None
    for cond in CONDS:
        p = os.path.join(d, "identity_size", cond, "identity_size.json")
        if not os.path.exists(p):
            continue
        j = json.load(open(p))
        res["identity_size"][cond] = j
        cell = lambda k: (f"{j[k]['per_tx']:.0f} (-{j[k]['saving_pct']:.0f}%)" if k in j else "-")
        print(f"{cond:9s} {j['transactions']:5d} {j['pem']['per_tx']:13.0f} {cell('der'):>16s} {cell('ref'):>16s} "
              f"{cell('gzip6'):>16s} {cell('xz6'):>16s} {cell('zstd3'):>16s}")
        if cond == "ecdsa":
            base_pem = j["pem"]["per_tx"]
    if base_pem:
        print("ratio to ECDSA as stored (PEM):")
        for cond, j in res["identity_size"].items():
            print(f"  {cond:9s} PEM x{j['pem']['per_tx'] / base_pem:5.2f}  DER x{j['der']['per_tx'] / base_pem:5.2f}"
                  f"  reference x{j['ref']['per_tx'] / base_pem:5.2f}")

    if out_json:
        json.dump(res, open(out_json, "w"), indent=1)
        print("\nwrote", out_json)


if __name__ == "__main__":
    a = sys.argv[1:]
    oj = None
    if "--json" in a:
        oj = a[a.index("--json") + 1]
        a = [x for x in a if x not in ("--json", oj)]
    main(a[0], oj)
SUMMARIZE_BLOCKCUT_EOF
cp "$0" "$OUT/tools/blockcut_run.sh" 2>/dev/null

echo "phase,cond,setting,rep,concurrency,n_tx,failed_workers,tx_per_s,mean_ms,p50_ms,p95_ms,p99_ms,wall_s,key_type,height_before,height_after" > "$CSV"

# ---------------------------------------------------------------- orderer settings
setting_values() {   # $1 = setting -> "PMB|BT|expected_bytes|expected_timeout"
  case $1 in
    pmb512k_bt2s)    echo "512 KB|2s|524288|2s" ;;
    pmb1m_bt2s)      echo "1 MB|2s|1048576|2s" ;;
    pmb512k_bt500ms) echo "512 KB|500ms|524288|500ms" ;;
    *) return 1 ;;
  esac
}
batch_line_counts_ok() {
  [ "$(grep -cE '^ *BatchTimeout:' "$CFG")" = 1 ] && [ "$(grep -cE '^ *PreferredMaxBytes:' "$CFG")" = 1 ]
}
set_batch() {   # $1 = PreferredMaxBytes, $2 = BatchTimeout
  MODIFIED=1
  sed -i -E "s/^( *PreferredMaxBytes:).*/\1 $1/; s/^( *BatchTimeout:).*/\1 $2/" "$CFG"
  grep -qE "^ *PreferredMaxBytes: $1\$" "$CFG" && grep -qE "^ *BatchTimeout: $2\$" "$CFG"
}

# ---------------------------------------------------------------- preflight
log "blockcut run start; out=$OUT; hours=$HOURS reps=$REPS raw_conds='$RAW_CONDS' cells='$CELLS' n=$N"
for b in peer configtxgen fabric-ca-client node python3 openssl docker git shuf awk sha256sum; do command -v $b >/dev/null || { log "ABORT: $b not on PATH"; exit 1; }; done
[ -f "$BENCH/node_modules/@hyperledger/fabric-gateway/package.json" ] || { log "ABORT: fabric-gateway not installed in $BENCH"; exit 1; }
[ -z "$DL" ] || [ -d "$DL" ] || { log "ABORT: DL=$DL is not a directory"; exit 1; }
cd "$TN" || exit 1
batch_line_counts_ok || { log "ABORT: expected exactly one BatchTimeout and one PreferredMaxBytes line in $CFG"; exit 1; }
if ! { grep -qE '^ *BatchTimeout: 2s$' "$CFG" && grep -qE '^ *PreferredMaxBytes: 512 KB$' "$CFG"; }; then
  # values this driver itself writes are left behind only by a run that was killed hard: restore them
  if grep -qE '^ *BatchTimeout: (2s|500ms)$' "$CFG" && grep -qE '^ *PreferredMaxBytes: (512 KB|1 MB)$' "$CFG"; then
    set_batch "512 KB" "2s" && log "restored BatchTimeout 2s and PreferredMaxBytes 512 KB left by an interrupted run"
  else
    log "ABORT: $CFG does not hold the defaults (BatchTimeout 2s, PreferredMaxBytes 512 KB):"; grep -E '^ *(BatchTimeout|MaxMessageCount|AbsoluteMaxBytes|PreferredMaxBytes):' "$CFG" >> "$LOG"; exit 1
  fi
fi
grep -qE '^ *MaxMessageCount: 10$' "$CFG" || { log "ABORT: MaxMessageCount is not 10 in $CFG"; exit 1; }
for cell in $CELLS; do
  case ${cell%%:*} in ecdsa|mldsa44|mldsa65|mldsa87|hybrid44) ;; *) log "ABORT: unknown condition in cell $cell"; exit 1 ;; esac
  setting_values "${cell#*:}" > /dev/null || { log "ABORT: unknown setting in cell $cell"; exit 1; }
done
for cond in $RAW_CONDS; do
  case $cond in ecdsa|mldsa44|mldsa65|mldsa87|hybrid44) ;; *) log "ABORT: unknown condition $cond in RAW_CONDS"; exit 1 ;; esac
done
trap 'rc=$?; [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null; kill $(jobs -p) 2>/dev/null; [ "$MODIFIED" = 1 ] && restore_defaults && log "configtx.yaml and CA files restored to the defaults"; log "script exit (code $rc)"' EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP
git -C "$TN" diff --stat >> "$LOG" 2>&1
{ echo "== machine"; uname -a; nproc; free -g; df -h ~ | tail -1; lscpu | grep -m1 "Model name"
  echo "== software"; node -v; node -p '"openssl " + process.versions.openssl'; go version 2>/dev/null
  echo "fabric-gateway $(node -p "require('$BENCH/node_modules/@hyperledger/fabric-gateway/package.json').version" 2>/dev/null)"
  docker version --format 'docker {{.Server.Version}}'
  for r in fabric fabric-ca fabric-lib-go; do echo "$r $(git -C ~/pqc/$r rev-parse --short HEAD 2>/dev/null) $(git -C ~/pqc/$r rev-parse --abbrev-ref HEAD 2>/dev/null)"; done
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}' | grep -E "fabric-(peer|orderer|ca):pqc|ccaas"
  peer version | head -4
  echo "== orderer batch settings in configtx.yaml before the run"; grep -E '^ *(BatchTimeout|MaxMessageCount|AbsoluteMaxBytes|PreferredMaxBytes):' "$CFG"
  echo "== bench client"; sha256sum "$BENCH/bench_night.mjs"; } > "$OUT/environment.txt" 2>&1

# ---------------------------------------------------------------- one condition = CA key request + channel capability
configure() {   # $1 = cond
  local cond=$1 algo="" size="" cap=V3_0
  case $cond in
    ecdsa)    ;;
    mldsa44)  algo=mldsa;        size=44 ;;
    mldsa65)  algo=mldsa;        size=65 ;;
    mldsa87)  algo=mldsa;        size=87 ;;
    hybrid44) algo=mldsa-hybrid; size=44; cap=V3_0_HYBRID ;;
    *) log "unknown cond $cond"; return 1 ;;
  esac
  cd "$TN" || return 1
  MODIFIED=1
  git checkout -q -- organizations/fabric-ca/ || return 1
  if [ -n "$algo" ]; then
    for o in org1 org2 ordererOrg; do
      sed -i "/^csr:\$/a\\   keyrequest:\\n     algo: $algo\\n     size: $size" organizations/fabric-ca/$o/fabric-ca-server-config.yaml
    done
    sed -i "/fabric-ca-client enroll/{/enrollment.profile tls/!s/fabric-ca-client enroll /fabric-ca-client enroll --csr.keyrequest.algo $algo --csr.keyrequest.size $size /}" organizations/fabric-ca/registerEnroll.sh
    [ "$(grep -c "keyrequest.algo $algo --" organizations/fabric-ca/registerEnroll.sh)" = 11 ] || { log "configure $cond: registerEnroll edit count wrong"; return 1; }
    [ "$(grep -c "algo: $algo\$" organizations/fabric-ca/*/fabric-ca-server-config.yaml | awk -F: '{s+=$2} END{print s}')" = 3 ] || { log "configure $cond: CA config edit wrong"; return 1; }
  fi
  sed -i -E '/Channel: &ChannelCapabilities/,/Orderer: &OrdererCapabilities/ s/V3_0(_HYBRID)?: true/'"$cap"': true/' configtx/configtx.yaml
  grep -A12 "Channel: &ChannelCapabilities" configtx/configtx.yaml | grep -q "^ *$cap: true" || { log "configure $cond: capability $cap not set"; return 1; }
  return 0
}

restore_defaults() {
  cd "$TN" && git checkout -q -- organizations/fabric-ca/ \
    && sed -i -E '/Channel: &ChannelCapabilities/,/Orderer: &OrdererCapabilities/ s/V3_0(_HYBRID)?: true/V3_0: true/' configtx/configtx.yaml \
    && set_batch "512 KB" "2s"
}

net_down() {
  cd "$TN" && ./network.sh down > "$1" 2>&1
  docker rm -f peer0org1_cityanchor_ccaas peer0org2_cityanchor_ccaas >/dev/null 2>&1   # network.sh's kill misses them
  true
}

der() { openssl x509 -in "$1" -outform DER 2>/dev/null | wc -c; }
height() { timeout 60 peer channel getinfo -c mychannel 2>/dev/null | grep -o '"height": *"\?[0-9]*' | grep -o '[0-9]*$'; }

# ---------------------------------------------------------------- one run
run_one() {   # $1 = phase (raw|main), $2 = cond, $3 = setting, $4 = rep ; returns 0 when a benchmark ran
  local phase=$1 cond=$2 setting=$3 rep=$4 t0=$(date +%s) D concs v pmb bt xb xt
  if [ "$phase" = raw ]; then D=$OUT/identity_size/$cond; concs=$RAW_CONCS; else D=$OUT/$cond/$setting/rep$rep; concs=$MAIN_CONCS; fi
  mkdir -p "$D"
  v=$(setting_values "$setting"); IFS='|' read -r pmb bt xb xt <<< "$v"
  net_down "$D/down.log"
  configure "$cond" || return 1
  set_batch "$pmb" "$bt" || { log "$cond $setting: could not set PreferredMaxBytes=$pmb BatchTimeout=$bt"; return 1; }
  cd "$TN"
  if ! bgwait timeout 900 ./network.sh up createChannel -c mychannel -ca > "$D/up.log" 2>&1 || ! grep -q "Channel 'mychannel' joined" "$D/up.log"; then
    log "$cond $setting rep$rep: network up FAILED (see $D/up.log)"; tail -5 "$D/up.log" >> "$LOG"; return 1; fi

  # the batch values actually written into the channel's genesis block
  local gb="" gt=""
  if FABRIC_CFG_PATH=$TN/configtx configtxgen -inspectBlock "$TN/channel-artifacts/mychannel.block" > "$D/genesis.json" 2> "$D/genesis.err" \
     && read -r gb gt < <(python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1]))["data"]["data"][0]["payload"]["data"]["config"]["channel_group"]["groups"]["Orderer"]["values"]
print(v["BatchSize"]["value"]["preferred_max_bytes"], v["BatchTimeout"]["value"]["timeout"])' "$D/genesis.json" 2>> "$D/genesis.err") \
     && [ -n "$gt" ]; then
    echo "preferred_max_bytes=$gb timeout=$gt" > "$D/batch_in_force.txt"
    if [ "$gb" != "$xb" ] || [ "$gt" != "$xt" ]; then
      log "$cond $setting rep$rep: genesis block holds preferred_max_bytes=$gb timeout=$gt, expected $xb $xt - run discarded"; return 1; fi
  else
    log "$cond $setting rep$rep: WARNING could not inspect the genesis block (see $D/genesis.err); continuing"
    echo "not verified" > "$D/batch_in_force.txt"
  fi

  if ! bgwait timeout 900 ./network.sh deployCCAAS -ccn cityanchor -ccp ~/pqc/cityanchor/chaincode > "$D/deploy.log" 2>&1 \
       || ! grep -q "Docker container started succesfully" "$D/deploy.log"; then
    log "$cond $setting rep$rep: deployCCAAS FAILED (see $D/deploy.log)"; tail -5 "$D/deploy.log" >> "$LOG"; return 1; fi

  # certificate sizes and key types of this network
  local O1=$TN/organizations/peerOrganizations/org1.example.com
  { echo "user1_msp_der $(der $O1/users/User1@org1.example.com/msp/signcerts/cert.pem)"
    echo "peer0org1_msp_der $(der $O1/peers/peer0.org1.example.com/msp/signcerts/cert.pem)"
    echo "orderer_msp_der $(der $TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/signcerts/orderer.example.com-cert.pem)"
    echo "ca_org1_der $(der $O1/peers/peer0.org1.example.com/msp/cacerts/localhost-7054-ca-org1.pem)"
    echo "peer0org1_tls_der $(der $O1/peers/peer0.org1.example.com/tls/signcerts/cert.pem)"
    echo "user1_msp_pem $(wc -c < $O1/users/User1@org1.example.com/msp/signcerts/cert.pem)"
    echo "user1_keystore_files $(ls $O1/users/User1@org1.example.com/msp/keystore | wc -l)"
    openssl x509 -in $O1/users/User1@org1.example.com/msp/signcerts/cert.pem -noout -text | grep -m2 "Public Key Algorithm\|Signature Algorithm"
  } > "$D/certs.txt" 2>&1

  # one AnchorAlert through the peer CLI (baseline protocol), after the chaincode servers have started
  local w try
  for w in $(seq 1 30); do
    docker logs peer0org1_cityanchor_ccaas 2>&1 | grep -q "Bootstrap process completed" \
      && docker logs peer0org2_cityanchor_ccaas 2>&1 | grep -q "Bootstrap process completed" && break
    sleep 2
  done
  sleep 5
  export FABRIC_CFG_PATH=$TN/../config/
  source ./scripts/envVar.sh > /dev/null; setGlobals 1 > /dev/null
  local hb; hb=$(height)
  for try in 1 2 3 4 5 6; do
  bgwait timeout 90 peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$TN/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem" -C mychannel -n cityanchor \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$O1/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    -c '{"function":"AnchorAlert","Args":["alert-1","Transport","dt8","abc123","1"]}' > "$D/invoke.log" 2>&1
    grep -q "status:200" "$D/invoke.log" && break
    cp "$D/invoke.log" "$D/invoke_try$try.log"; log "$cond $setting rep$rep: invoke attempt $try failed ($(grep -o "connect: [a-z ]*\|status:[0-9]*" "$D/invoke.log" | tail -1)), retrying in 10 s"
    sleep 10
  done
  grep -q "status:200" "$D/invoke.log" && [ "$try" -gt 1 ] && log "$cond $setting rep$rep: invoke succeeded on attempt $try"
  if ! grep -q "status:200" "$D/invoke.log"; then
    log "$cond $setting rep$rep: smoke invoke FAILED after 6 attempts"; tail -1 "$D/invoke.log" | tail -c 600 >> "$LOG"
    for c in peer0.org1.example.com orderer.example.com; do echo "-- $c" >> "$D/container_tail.log"; docker logs --tail 40 $c >> "$D/container_tail.log" 2>&1; done
    return 1; fi
  # the invoke returns once the orderer accepts it; wait until its block is on the peer (up to 30 s)
  if [ -n "$hb" ]; then
    for w in $(seq 1 30); do [ "$(height)" -gt "$hb" ] 2>/dev/null && break; sleep 1; done
    [ "$(height)" -gt "$hb" ] 2>/dev/null || log "$cond $setting rep$rep: WARNING height did not rise after the CLI invoke"
  fi
  sleep 3

  local C ok=0 h0 h1
  for C in $concs; do
    h0=$(height)
    [ -n "$h0" ] || log "$cond $setting rep$rep c$C: WARNING ledger height not read (peer channel getinfo); block counts will be assigned by transaction count"
    ( while :; do docker stats --no-stream --format "$(date +%s),{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}" >> "$D/stats_c$C.csv" 2>/dev/null; sleep 2; done ) &
    local SP=$!
    ( cd "$BENCH" && FABRIC_SAMPLES=~/pqc/fabric-samples OUT_JSON="$D/bench_c$C.json" COND=$cond REP=$rep \
        exec timeout 600 node bench_night.mjs $N $C ) > "$D/bench_c$C.log" 2>&1 &
    CHILD=$!; wait "$CHILD"; CHILD=""
    kill $SP 2>/dev/null; wait $SP 2>/dev/null
    sleep 3                      # let the last block commit on the peer before reading the height
    h1=$(height)
    if [ -s "$D/bench_c$C.json" ]; then
      node -e "const f=(x,d)=>Number(x).toFixed(d);const r=require('$D/bench_c$C.json');const l=r.latency_ms||{};console.log(['$phase','$cond','$setting',$rep,r.concurrency,r.n_tx,r.failed_workers,f(r.tx_per_s,2),f(l.mean,1),f(l.p50,1),f(l.p95,1),f(l.p99,1),f(r.wall_s,2),r.key_type,'$h0','$h1'].join(','))" >> "$CSV"
      log "$cond $setting rep$rep c$C: $(tail -1 "$CSV" | cut -d, -f6-9,12,15-16)"; ok=$((ok+1))
    else
      log "$cond $setting rep$rep c$C: bench FAILED"; tail -3 "$D/bench_c$C.log" >> "$LOG"
    fi
    [ "$C" = 50 ] && docker exec peer0.org1.example.com du -sb /var/hyperledger/production/ledgersData > "$D/du_after_c20_c50.txt" 2>&1
    sleep 5
  done
  docker exec peer0.org1.example.com du -sb /var/hyperledger/production/ledgersData > "$D/du_end.txt" 2>&1
  docker exec peer0.org1.example.com ls -l /var/hyperledger/production/ledgersData/chains/chains/mychannel > "$D/blockfiles_ls.txt" 2>&1

  # block files: per-block counts (every run); identity-size rebuild and compression (phase 1); then delete
  if [ $ok -gt 0 ]; then
    local f files=()
    mkdir -p "$D/raw"
    for f in $(docker exec peer0.org1.example.com ls /var/hyperledger/production/ledgersData/chains/chains/mychannel | grep '^blockfile_' | sort); do
      docker cp peer0.org1.example.com:/var/hyperledger/production/ledgersData/chains/chains/mychannel/$f "$D/raw/$f" > /dev/null 2>&1 && files+=("$D/raw/$f")
    done
    if [ ${#files[@]} -gt 0 ]; then
      python3 -I "$OUT/tools/block_sizes.py" "${files[@]}" --json "$D/blocks.json" > "$D/blocks.txt" 2>&1 \
        && log "$cond $setting rep$rep: blocks $(cat "$D/blocks.txt")" || log "$cond $setting rep$rep: block scan FAILED (see $D/blocks.txt)"
      if [ "$phase" = raw ]; then
        python3 -I "$OUT/tools/mitigation_estimate.py" "${files[@]}" --json "$D/identity_size.json" > "$D/identity_size.txt" 2>&1 \
          && log "$cond: identity size $(tr '\n' ' ' < "$D/identity_size.txt")" || log "$cond: identity-size estimate FAILED (see $D/identity_size.txt)"
      fi
    else
      log "$cond $setting rep$rep: no block files copied"
    fi
    rm -rf "$D/raw"
  fi
  log "$cond $setting rep$rep: done in $(( $(date +%s) - t0 )) s ($ok/$(echo $concs | wc -w) benchmarks)"
  [ $ok -gt 0 ]
}

stop_now() {
  if [ "$(date +%s)" -ge "$END" ]; then log "deadline reached"; return 0; fi
  if [ -f ~/pqc/STOP_BLOCKCUT ]; then log "STOP_BLOCKCUT found"; return 0; fi
  return 1
}
finish_run() {   # $1 = start time of the run, $2 = label
  sleep 20
  DONE_RUNS=$(( DONE_RUNS + 1 )); RUN_SECS=$(( RUN_SECS + $(date +%s) - $1 ))
  progress "finished $2"
}

# ---------------------------------------------------------------- plan
NRAW=$(printf '%s\n' $RAW_CONDS | grep -c .); NCELLS=$(printf '%s\n' $CELLS | grep -c .)
PLANNED=$(( NRAW + REPS * NCELLS ))
progress "start ($NRAW identity-size runs, then $REPS repetitions of $NCELLS cells)"

# ---------------------------------------------------------------- phase 1: identity size
STOPPED=0
for cond in $RAW_CONDS; do
  stop_now && { STOPPED=1; break; }
  progress "identity size: $cond"; t_run=$(date +%s)
  run_one raw "$cond" pmb512k_bt2s 1 || log "$cond: identity-size run failed"
  finish_run "$t_run" "identity size: $cond"
done

# ---------------------------------------------------------------- phase 2: block cutting, shuffled cell order per repetition
ACTIVE="$CELLS"; declare -A FAILS
in_active() { printf '%s\n' $ACTIVE | grep -qx "$1"; }
for rep in $(seq 1 "$REPS"); do
  [ "$STOPPED" = 1 ] && break
  mapfile -t ORDER < <(printf '%s\n' $ACTIVE | shuf)
  log "=== repetition $rep order: ${ORDER[*]}"
  for cell in "${ORDER[@]}"; do
    in_active "$cell" || continue
    stop_now && { STOPPED=1; break 2; }
    progress "running $cell rep $rep"; t_run=$(date +%s)
    if run_one main "${cell%%:*}" "${cell#*:}" "$rep"; then FAILS[$cell]=0; else
      FAILS[$cell]=$(( ${FAILS[$cell]:-0} + 1 ))
      if [ "${FAILS[$cell]}" -ge 2 ]; then
        ACTIVE=$(printf '%s\n' $ACTIVE | grep -vx "$cell" | xargs)
        PLANNED=$(( PLANNED - (REPS - rep) ))
        log "dropping $cell after 2 failures in a row; active: $ACTIVE"
      fi
    fi
    finish_run "$t_run" "$cell rep $rep"
  done
  log "=== repetition $rep finished; elapsed $(( ($(date +%s) - START) / 60 )) min"
  [ -z "$ACTIVE" ] && break
done

# ---------------------------------------------------------------- wrap up
net_down "$OUT/final_down.log"; restore_defaults && MODIFIED=0 && log "configtx.yaml and CA files restored to the defaults"
log "summary rows: $(( $(wc -l < "$CSV") - 1 ))"
python3 -I "$OUT/tools/summarize_blockcut.py" "$OUT" > "$OUT/summary_tables.txt" 2>&1 && log "wrote summary_tables.txt" || log "summarize_blockcut.py FAILED (see summary_tables.txt)"
NAME=$(basename "$OUT")
tar czf ~/pqc/results/$NAME.tgz -C ~/pqc/results --exclude='blockfile_00000*' "$NAME" && log "packed: ~/pqc/results/$NAME.tgz ($(stat -c %s ~/pqc/results/$NAME.tgz) B)"
PACK=~/pqc/results/$NAME.tgz
if [ -n "$DL" ]; then
  cp ~/pqc/results/$NAME.tgz "$DL/" && cp "$CSV" "$DL/${NAME}_summary.csv" && PACK=$DL/$NAME.tgz && log "copied to $DL"
fi
log "ALL DONE - results: $PACK"
touch "$OUT/DONE"
{ echo "finished $(date '+%F %T') - total time $(hm $(( $(date +%s) - START ))), $DONE_RUNS runs"; echo "results: $PACK"; } > "$STATUS"
cat "$STATUS"
