#!/usr/bin/env bash
# night_run.sh - unattended overnight benchmark: ECDSA vs ML-DSA-44/65/87 vs hybrid (ML-DSA-44) on the
# UFRN-Itau post-quantum Fabric fork. Baseline protocol (1 CLI invoke, then 2,000 alerts at concurrency 20
# and 50, then 10 and 100), repeated with a fresh network per run.
#
# Start (inside WSL, keep the terminal window open):
#   DL=/path/to/a/folder setsid nohup bash ~/pqc/night_run.sh > ~/pqc/night_console.log 2>&1 &
#   (DL is optional: when set, the packed results are also copied there)
#   sleep 30; tail -f ~/pqc/results/night_*/progress.log        # Ctrl+C stops only the tail, not the run
#   Progress at any time:  cat ~/pqc/night_status.txt
# Stop early:   touch ~/pqc/STOP_NIGHT     (finishes the current run, then packs the results)
#
# Tunables (environment): HOURS=9.5  MAX_REPS=10  CONDS="ecdsa mldsa44 mldsa65 mldsa87 hybrid44"
# It never touches other Fabric networks: everything runs under compose project "pqcnet" in ~/pqc.
# no 'set -u': fabric-samples' envVar.sh reads unset variables (e.g. OVERRIDE_ORG)
HOURS=${HOURS:-9.5}; MAX_REPS=${MAX_REPS:-10}
CONDS=${CONDS:-"ecdsa mldsa44 mldsa65 mldsa87 hybrid44"}
CONCS="20 50 10 100"; N=2000
TN=~/pqc/fabric-samples/test-network; BENCH=~/pqc/cityanchor/bench
DL=${DL:-}
OUT=~/pqc/results/night_$(date +%Y%m%d_%H%M); mkdir -p "$OUT/tools"
LOG=$OUT/progress.log; CSV=$OUT/summary.csv; STATUS=~/pqc/night_status.txt
export COMPOSE_PROJECT_NAME=pqcnet PATH=~/pqc/bin:$PATH
START=$(date +%s); END=$(awk -v h="$HOURS" -v n="$START" 'BEGIN{printf "%d", n + h*3600}')
rm -f ~/pqc/STOP_NIGHT

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
trap 'log "script exit (code $?)"' EXIT

# ---------------------------------------------------------------- progress / ETA
DONE_RUNS=0; RUN_SECS=0; AVG_GUESS=270      # seconds per run before the first one is measured
hm() { local s=$1; [ "$s" -lt 0 ] && s=0; printf '%dh %02dm' $((s/3600)) $(((s%3600)/60)); }
in_active() { printf '%s\n' $ACTIVE | grep -qx "$1"; }
remaining_runs() {   # $1 = rep, $2 = first index of ORDER still to run (in this rep)
  local r=$1 i=$2 n=0 j nact
  for ((j=i; j<${#ORDER[@]}; j++)); do in_active "${ORDER[$j]}" && n=$((n+1)); done
  nact=$(printf '%s\n' $ACTIVE | grep -c .)
  echo $(( n + (MAX_REPS - r) * nact ))
}
progress() {   # $1 = remaining runs, $2 = what is happening now
  local remain=$1 now=$(date +%s) avg total pct left eta note=""
  if [ "$DONE_RUNS" -gt 0 ]; then avg=$(( RUN_SECS / DONE_RUNS )); else avg=$AVG_GUESS; fi
  total=$(( DONE_RUNS + remain )); pct=100; [ "$total" -gt 0 ] && pct=$(( 100 * DONE_RUNS / total ))
  left=$(( remain * avg + 90 )); eta=$(( now + left ))
  if [ "$eta" -gt "$END" ]; then eta=$END; left=$(( END - now )); note=" - the ${HOURS} h limit will be reached before all runs finish"; fi
  local line="progress ${pct}% (${DONE_RUNS}/${total} runs) | elapsed $(hm $((now-START))) | remaining ~$(hm $left) | expected finish $(date -d @$eta '+%H:%M (%d/%m)')${note} | avg $((avg/60))m $((avg%60))s per run | now: $2"
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
cat > "$OUT/tools/decode_blockfile.py" <<'DECODE_EOF'
"""Byte composition of a Hyperledger Fabric peer block file.

Reads a Fabric peer block file (ledgersData/chains/chains/<channel>/blockfile_000000).
The peer stores each block as [varint length][serialized block], where the serialized
block is fabric's own layout (common/ledger/blkstorage/block_serialization.go):
  varint header.Number | len+DataHash | len+PreviousHash | varint tx count |
  (len+Envelope bytes) x tx count | varint metadata count | (len+metadata item) x count
A dependency-free protobuf wire parser then attributes every byte to one of:

  block header            Block.header hashes (previous hash, data hash; the block-number varint is counted as framing)
  block metadata          Block.metadata (orderer/validator signatures, tx validity flags)
  envelope signature      Envelope.signature (the client's signature over the payload)
  payload header          Payload.header: channel header + signature header (creator cert)
  proposal payload        ChaincodeActionPayload.chaincode_proposal_payload
                          (chaincode name, function and arguments = the alert itself)
  read/write set          ChaincodeAction.results (TxReadWriteSet)
  response / events       ChaincodeAction.response + events + chaincode_id (here: no events; the
                          response carries a second copy of the stored JSON alert)
  endorsements            Endorsement.endorser (cert) + Endorsement.signature, per endorser
  framing                 protobuf tags/lengths and the file's length prefixes

Field numbers follow fabric-protos (common/common.proto, peer/transaction.proto,
peer/proposal.proto, peer/proposal_response.proto):
  Block{1 header, 2 data, 3 metadata}; BlockData{1 data: Envelope[]}; BlockMetadata{1 metadata[]}
  Envelope{1 payload, 2 signature}; Payload{1 header{1 channel_header, 2 signature_header}, 2 data}
  ChannelHeader{1 type, ...}; Transaction{1 actions[]}; TransactionAction{1 header, 2 payload}
  ChaincodeActionPayload{1 chaincode_proposal_payload, 2 action}
  ChaincodeEndorsedAction{1 proposal_response_payload, 2 endorsements[]}
  ProposalResponsePayload{1 proposal_hash, 2 extension=ChaincodeAction}
  ChaincodeAction{1 results, 2 events, 3 response, 4 chaincode_id}; Endorsement{1 endorser, 2 signature}

Usage: python decode_blockfile.py blockfile_000000 [--json out.json]
"""
import sys, json, collections


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; r |= (c & 0x7F) << s; i += 1
        if not c & 0x80: return r, i
        s += 7


def fields(b):
    """Yield (field_no, wire_type, value_bytes_or_int, total_bytes_of_this_field)."""
    i, n = 0, len(b)
    while i < n:
        start = i; key, i = varint(b, i); f, wt = key >> 3, key & 7
        if wt == 0: v, i = varint(b, i)
        elif wt == 2: ln, i = varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1: v = b[i:i + 8]; i += 8
        elif wt == 5: v = b[i:i + 4]; i += 4
        else: raise ValueError(f"wire type {wt}")
        yield f, wt, v, i - start


def sub(b, no):
    return [v for f, wt, v, _ in fields(b) if f == no and wt == 2]


def header_type(payload_header):
    """ChannelHeader.type (1 = CONFIG, 3 = ENDORSER_TRANSACTION) from Payload.header."""
    for f, wt, v, _ in fields(payload_header):
        if f == 1:
            for cf, cwt, cv, _ in fields(v):
                if cf == 1 and cwt == 0: return cv
    return None


def decode_envelope(env, acc):
    payload = sub(env, 1)[0]
    htype = header_type(sub(payload, 1)[0])
    if htype != 3:                                   # config / genesis envelope: count whole, do not dissect
        acc["config_tx"] += 1; acc["config_envelope_bytes"] += len(env); return
    acc["tx"] += 1
    for ef, ewt, ev, _ in fields(env):
        if ef == 2: acc["envelope_signature"] += len(ev)
        elif ef == 1:
            for pf, pwt, pv, _ in fields(ev):
                if pf == 1: acc["payload_header"] += len(pv)
                elif pf == 2:                     # Transaction
                    for action in sub(pv, 1):
                        for af, awt, av, _ in fields(action):
                            if af == 1: acc["action_header"] += len(av)
                            elif af == 2:          # ChaincodeActionPayload
                                for cf, cwt, cv, _ in fields(av):
                                    if cf == 1: acc["proposal_payload"] += len(cv)
                                    elif cf == 2:  # ChaincodeEndorsedAction
                                        for xf, xwt, xv, _ in fields(cv):
                                            if xf == 1:    # ProposalResponsePayload
                                                for rf, rwt, rv, _ in fields(xv):
                                                    if rf == 1: acc["proposal_hash"] += len(rv)
                                                    elif rf == 2:   # ChaincodeAction
                                                        for gf, gwt, gv, _ in fields(rv):
                                                            if gf == 1: acc["rwset"] += len(gv)
                                                            else: acc["response_events_ccid"] += len(gv)
                                            elif xf == 2:  # Endorsement
                                                acc["endorsements"] += 1
                                                for nf, nwt, nv, _ in fields(xv):
                                                    if nf == 1: acc["endorser_cert"] += len(nv)
                                                    elif nf == 2: acc["endorser_signature"] += len(nv)


def decode_block(blk, acc):
    """fabric's serialized block layout (see module docstring)."""
    acc["block_bytes"] += len(blk); i = 0
    number, i = varint(blk, i)
    ln, i = varint(blk, i); i += ln; dh = ln                  # DataHash
    ln, i = varint(blk, i); i += ln; ph = ln                  # PreviousHash
    acc["block_header"] += dh + ph
    ntx, i = varint(blk, i)
    for _ in range(ntx):
        ln, i = varint(blk, i); decode_envelope(blk[i:i + ln], acc); i += ln
    nmeta, i = varint(blk, i)                                 # BlockMetadata: count, then len+item each
    for _ in range(nmeta):
        ln, i = varint(blk, i); acc["block_metadata"] += ln; i += ln
    assert i == len(blk), (i, len(blk))
    acc["last_block_number"] = number


def main(path, out=None):
    b = open(path, "rb").read(); i = 0; acc = collections.Counter(); blocks = 0; prefix = 0
    while i < len(b):
        ln, j = varint(b, i); prefix += j - i; blk = b[j:j + ln]; i = j + ln
        decode_block(blk, acc); blocks += 1
    cats = ["config_envelope_bytes", "block_header", "block_metadata", "envelope_signature", "payload_header", "action_header", "proposal_payload",
            "proposal_hash", "rwset", "response_events_ccid", "endorser_cert", "endorser_signature"]
    attributed = sum(acc[c] for c in cats)
    framing = acc["block_bytes"] - attributed
    res = dict(file=path, file_bytes=len(b), blocks=blocks, last_block_number=acc["last_block_number"],
               transactions=acc["tx"], config_transactions=acc["config_tx"], endorsements=acc["endorsements"],
               length_prefix_bytes=prefix, block_bytes=acc["block_bytes"], framing_bytes=framing,
               bytes={c: acc[c] for c in cats},
               share={c: round(100 * acc[c] / len(b), 2) for c in cats},
               per_tx_bytes={c: round(acc[c] / max(acc["tx"], 1), 1) for c in cats},
               file_bytes_per_tx=round(len(b) / max(acc["tx"], 1), 1))
    res["share"]["framing"] = round(100 * (framing + prefix) / len(b), 2)
    print(json.dumps(res, indent=1))
    if out: json.dump(res, open(out, "w"), indent=1)
    return res


if __name__ == "__main__":
    args = sys.argv[1:]; out = None
    if "--json" in args: out = args[args.index("--json") + 1]; args = [a for a in args if a not in ("--json", out)]
    main(args[0], out)
DECODE_EOF
cp "$0" "$OUT/tools/night_run.sh" 2>/dev/null

echo "cond,rep,concurrency,n_tx,failed_workers,tx_per_s,mean_ms,p50_ms,p95_ms,p99_ms,wall_s,key_type" > "$CSV"

# ---------------------------------------------------------------- preflight
log "night run start; out=$OUT; hours=$HOURS max_reps=$MAX_REPS conds='$CONDS' concs='$CONCS' n=$N"
for b in peer configtxgen fabric-ca-client node python3 openssl docker git shuf awk; do command -v $b >/dev/null || { log "ABORT: $b not on PATH"; exit 1; }; done
[ -f "$BENCH/node_modules/@hyperledger/fabric-gateway/package.json" ] || { log "ABORT: fabric-gateway not installed in $BENCH"; exit 1; }
[ -z "$DL" ] || [ -d "$DL" ] || { log "ABORT: DL=$DL is not a directory"; exit 1; }
cd "$TN" || exit 1
git -C "$TN" diff --stat >> "$LOG" 2>&1
{ echo "== machine"; uname -a; nproc; free -g; df -h ~ | tail -1; node -v; go version 2>/dev/null
  docker version --format 'docker {{.Server.Version}}'; docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}' | grep -E "fabric-(peer|orderer|ca):pqc|ccaas"
  peer version | head -4; } > "$OUT/environment.txt" 2>&1

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
    && sed -i -E '/Channel: &ChannelCapabilities/,/Orderer: &OrdererCapabilities/ s/V3_0(_HYBRID)?: true/V3_0: true/' configtx/configtx.yaml
}

net_down() {
  cd "$TN" && ./network.sh down > "$1" 2>&1
  docker rm -f peer0org1_cityanchor_ccaas peer0org2_cityanchor_ccaas >/dev/null 2>&1   # network.sh's kill misses them
  true
}

der() { openssl x509 -in "$1" -outform DER 2>/dev/null | wc -c; }

# ---------------------------------------------------------------- one run
run_one() {   # $1 = cond, $2 = rep ; returns 0 when the benchmarks ran
  local cond=$1 rep=$2 D=$OUT/$1/rep$2 t0=$(date +%s)
  mkdir -p "$D"
  net_down "$D/down.log"
  configure "$cond" || return 1
  cd "$TN"
  if ! timeout 900 ./network.sh up createChannel -c mychannel -ca > "$D/up.log" 2>&1 || ! grep -q "Channel 'mychannel' joined" "$D/up.log"; then
    log "$cond rep$rep: network up FAILED (see $D/up.log)"; tail -5 "$D/up.log" >> "$LOG"; return 1; fi
  if ! timeout 900 ./network.sh deployCCAAS -ccn cityanchor -ccp ~/pqc/cityanchor/chaincode > "$D/deploy.log" 2>&1 \
       || ! grep -q "Docker container started succesfully" "$D/deploy.log"; then
    log "$cond rep$rep: deployCCAAS FAILED (see $D/deploy.log)"; tail -5 "$D/deploy.log" >> "$LOG"; return 1; fi

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

  # one AnchorAlert through the peer CLI (baseline protocol); with the 4000 of c20 + c50 the ledger holds 4,001 alerts
  # The chaincode servers need a few seconds to start after deployCCAAS; an invoke sent earlier is
  # refused ("connect: connection refused"). Wait until both log "Bootstrap process completed", then
  # allow up to 6 attempts 10 s apart (a refused invoke writes nothing to the ledger).
  local w try
  for w in $(seq 1 30); do
    docker logs peer0org1_cityanchor_ccaas 2>&1 | grep -q "Bootstrap process completed" \
      && docker logs peer0org2_cityanchor_ccaas 2>&1 | grep -q "Bootstrap process completed" && break
    sleep 2
  done
  sleep 5
  export FABRIC_CFG_PATH=$TN/../config/
  source ./scripts/envVar.sh > /dev/null; setGlobals 1 > /dev/null
  for try in 1 2 3 4 5 6; do
  timeout 90 peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$TN/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem" -C mychannel -n cityanchor \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$O1/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    -c '{"function":"AnchorAlert","Args":["alert-1","Transport","dt8","abc123","1"]}' > "$D/invoke.log" 2>&1
    grep -q "status:200" "$D/invoke.log" && break
    cp "$D/invoke.log" "$D/invoke_try$try.log"; log "$cond rep$rep: invoke attempt $try failed ($(grep -o "connect: [a-z ]*\|status:[0-9]*" "$D/invoke.log" | tail -1)), retrying in 10 s"
    sleep 10
  done
  grep -q "status:200" "$D/invoke.log" && [ "$try" -gt 1 ] && log "$cond rep$rep: invoke succeeded on attempt $try"
  if ! grep -q "status:200" "$D/invoke.log"; then
    log "$cond rep$rep: smoke invoke FAILED after 6 attempts"; tail -1 "$D/invoke.log" | tail -c 600 >> "$LOG"
    for c in peer0.org1.example.com orderer.example.com; do echo "-- $c" >> "$D/container_tail.log"; docker logs --tail 40 $c >> "$D/container_tail.log" 2>&1; done
    return 1; fi
  sleep 3

  local C ok=0
  for C in $CONCS; do
    ( while :; do docker stats --no-stream --format "$(date +%s),{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}" >> "$D/stats_c$C.csv" 2>/dev/null; sleep 2; done ) &
    local SP=$!
    ( cd "$BENCH" && FABRIC_SAMPLES=~/pqc/fabric-samples OUT_JSON="$D/bench_c$C.json" COND=$cond REP=$rep \
        timeout 600 node bench_night.mjs $N $C ) > "$D/bench_c$C.log" 2>&1
    kill $SP 2>/dev/null; wait $SP 2>/dev/null
    if [ -s "$D/bench_c$C.json" ]; then
      node -e "const f=(x,d)=>Number(x).toFixed(d);const r=require('$D/bench_c$C.json');const l=r.latency_ms||{};console.log(['$cond',$rep,r.concurrency,r.n_tx,r.failed_workers,f(r.tx_per_s,2),f(l.mean,1),f(l.p50,1),f(l.p95,1),f(l.p99,1),f(r.wall_s,2),r.key_type].join(','))" >> "$CSV"
      log "$cond rep$rep c$C: $(tail -1 "$CSV" | cut -d, -f4-7,10)"; ok=$((ok+1))
    else
      log "$cond rep$rep c$C: bench FAILED"; tail -3 "$D/bench_c$C.log" >> "$LOG"
    fi
    [ "$C" = 50 ] && docker exec peer0.org1.example.com du -sb /var/hyperledger/production/ledgersData > "$D/du_after_c20_c50.txt" 2>&1
    sleep 5
  done
  docker exec peer0.org1.example.com du -sb /var/hyperledger/production/ledgersData > "$D/du_end.txt" 2>&1
  docker exec peer0.org1.example.com ls -l /var/hyperledger/production/ledgersData/chains/chains/mychannel > "$D/blockfiles_ls.txt" 2>&1

  # byte composition: decode the block files of the first successful run of each condition
  if [ ! -f "$OUT/$cond/.decoded" ] && [ $ok -gt 0 ]; then
    for f in blockfile_000000 blockfile_000001; do
      docker cp peer0.org1.example.com:/var/hyperledger/production/ledgersData/chains/chains/mychannel/$f "$D/$f" > /dev/null 2>&1 || continue
      python3 -I "$OUT/tools/decode_blockfile.py" "$D/$f" --json "$D/decode_$f.json" > /dev/null 2>&1 \
        && log "$cond rep$rep: decoded $f ($(stat -c %s "$D/$f") B)" || log "$cond rep$rep: decode of $f FAILED"
      [ "$cond" = ecdsa ] || rm -f "$D/$f"          # keep raw block files only for ECDSA (small); the JSON keeps the rest
    done
    touch "$OUT/$cond/.decoded"
  fi
  log "$cond rep$rep: done in $(( $(date +%s) - t0 )) s ($ok/4 benchmarks)"
  [ $ok -gt 0 ]
}

# ---------------------------------------------------------------- main loop: shuffled condition order in every repetition
ACTIVE="$CONDS"; declare -A FAILS; ORDER=()
progress "$(( MAX_REPS * $(printf '%s\n' $ACTIVE | grep -c .) ))" "start"
for rep in $(seq 1 "$MAX_REPS"); do
  mapfile -t ORDER < <(printf '%s\n' $ACTIVE | shuf)
  log "=== repetition $rep order: ${ORDER[*]}"
  for ((k=0; k<${#ORDER[@]}; k++)); do
    cond=${ORDER[$k]}
    in_active "$cond" || continue
    if [ "$(date +%s)" -ge "$END" ]; then log "deadline reached"; break 2; fi
    if [ -f ~/pqc/STOP_NIGHT ]; then log "STOP_NIGHT found"; break 2; fi
    progress "$(remaining_runs "$rep" "$k")" "running $cond rep $rep"
    t_run=$(date +%s)
    if run_one "$cond" "$rep"; then FAILS[$cond]=0; else
      FAILS[$cond]=$(( ${FAILS[$cond]:-0} + 1 ))
      if [ "${FAILS[$cond]}" -ge 2 ]; then ACTIVE=$(printf '%s\n' $ACTIVE | grep -vx "$cond" | xargs); log "dropping $cond after 2 failures in a row; active: $ACTIVE"; fi
    fi
    sleep 20
    DONE_RUNS=$(( DONE_RUNS + 1 )); RUN_SECS=$(( RUN_SECS + $(date +%s) - t_run ))
    progress "$(remaining_runs "$rep" "$((k+1))")" "finished $cond rep $rep"
  done
  log "=== repetition $rep finished; elapsed $(( ($(date +%s) - START) / 60 )) min"
  [ -z "$ACTIVE" ] && break
done

# ---------------------------------------------------------------- wrap up
net_down "$OUT/final_down.log"; restore_defaults
log "summary rows: $(( $(wc -l < "$CSV") - 1 ))"
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
