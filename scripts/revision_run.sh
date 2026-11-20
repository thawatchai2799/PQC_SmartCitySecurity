#!/usr/bin/env bash
# revision_run.sh - experiments for the major revision, on the post-quantum Fabric fork, unattended.
#
#   Phase A  one network per condition (default: all five). On each:
#              E5  2,000 alerts at 20 clients after the CLI invoke (the ledger of Table 12), then its block
#                  files are compressed one block at a time: gzip -6, zstd -3, zstd -3 with a dictionary of
#                  the channel's certificates, and zstd -3 with a trained dictionary (tools/blockcomp.py)
#              E1  negative controls: tampered client, proposal and endorsement signatures, an endorsement
#                  by the other organisation's certificate, the other ML-DSA parameter set, and (Hybrid-44)
#                  a valid ECDSA signature by the classical key (tools/negctl.mjs)
#              E2  the TLS key exchange of every node-to-node connection: the peers are restarted while
#                  tcpdump captures the Docker bridge, then a short benchmark runs (tools/tlshello.py)
#   Phase B  E4 long run (default ECDSA and ML-DSA-44): 100,000 alerts at 50 clients in chunks of 10,000;
#            after each chunk the peer's ledger directories, the orderer's ledger and the height are recorded
#   Phase C  E3 constrained network (default ECDSA, ML-DSA-44, ML-DSA-87; 10 repetitions, shuffled order):
#            on each fresh network 2,000 alerts at 20 clients are run twice, once with and once without
#            10 ms delay and a 100 Mbit/s rate on every node's traffic to the other nodes (20 ms round trip
#            between organisations; client and chaincode traffic untouched), in random order
#
# Usage (inside WSL):
#   bash ~/pqc/revision_run.sh check     preflight only (a few minutes: pulls the helper image); starts no network
#   bash ~/pqc/revision_run.sh smoke     every step once with small sizes (about 25 minutes)
#   setsid nohup bash ~/pqc/revision_run.sh full > ~/pqc/revision_console.log 2>&1 &     (about 3 hours)
#   Progress: cat ~/pqc/revision_status.txt      Stop early: touch ~/pqc/STOP_REVISION
# The packed results are copied to DL when it is set (for example DL=/mnt/c/Users/<name>/Downloads).
# It never touches other Fabric networks: everything runs under compose project "pqcnet" in ~/pqc.
# no 'set -u': fabric-samples' envVar.sh reads unset variables (e.g. OVERRIDE_ORG)
MODE=${1:-}
case $MODE in check|smoke|full) ;; *) echo "usage: bash $0 check|smoke|full"; exit 2 ;; esac
if [ "$MODE" = smoke ]; then
  A_CONDS=${A_CONDS-"ecdsa mldsa44 hybrid44"}; A_N=${A_N:-200}
  B_CONDS=${B_CONDS-"mldsa44"}; B_ALERTS=${B_ALERTS:-2000}; B_CHUNK=${B_CHUNK:-1000}
  C_CONDS=${C_CONDS-"mldsa44"}; C_REPS=${C_REPS:-1}; C_N=${C_N:-200}
  HOURS=${HOURS:-1}
else
  A_CONDS=${A_CONDS-"ecdsa mldsa44 mldsa65 mldsa87 hybrid44"}; A_N=${A_N:-2000}
  B_CONDS=${B_CONDS-"ecdsa mldsa44"}; B_ALERTS=${B_ALERTS:-100000}; B_CHUNK=${B_CHUNK:-10000}
  C_CONDS=${C_CONDS-"ecdsa mldsa44 mldsa87"}; C_REPS=${C_REPS:-10}; C_N=${C_N:-2000}
  HOURS=${HOURS:-7}
fi
A_CONC=20; B_CONC=50; C_CONC=20
C_DELAY=${C_DELAY:-10ms}; C_RATE=${C_RATE:-100mbit}      # per node egress to the other nodes
NETSHOOT=${NETSHOOT:-nicolaka/netshoot:v0.13}
BENCH_SHA=1431ee5fd622a651be9b0b898f3f0e3f738e0ba808a209b0ea1c22efb2292f6f   # the client of the paper's runs
TN=~/pqc/fabric-samples/test-network; BENCH=~/pqc/cityanchor/bench; CFG=$TN/configtx/configtx.yaml
DL=${DL:-}
OUT=~/pqc/results/revision_${MODE}_$(date +%Y%m%d_%H%M%S); mkdir -p "$OUT/tools"
LOG=$OUT/progress.log; CSV=$OUT/summary.csv; STATUS=~/pqc/revision_status.txt
export COMPOSE_PROJECT_NAME=pqcnet PATH=~/pqc/bin:$PATH
START=$(date +%s); END=$(awk -v h="$HOURS" -v n="$START" 'BEGIN{printf "%d", n + h*3600}')
rm -f ~/pqc/STOP_REVISION
MODIFIED=0     # set to 1 once configtx.yaml or the CA files have been edited; the exit trap then restores them
CAP=pqc_revision_capture   # name of the capture container

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
# Long steps run in the background and are waited for, so that a TERM/INT/HUP is handled at once
# (bash defers traps while a foreground command runs); the exit trap then stops CHILD.
CHILD=""
bgwait() { "$@" & CHILD=$!; wait "$CHILD"; local rc=$?; CHILD=""; return $rc; }

# ---------------------------------------------------------------- progress / ETA
declare -A AVG_GUESS=([A]=330 [B]=900 [C]=230) PH_SECS=([A]=0 [B]=0 [C]=0) PH_DONE=([A]=0 [B]=0 [C]=0) PH_PLAN=([A]=0 [B]=0 [C]=0)
hm() { local s=$1; [ "$s" -lt 0 ] && s=0; printf '%dh %02dm' $((s/3600)) $(((s%3600)/60)); }
progress() {   # $1 = what is happening now
  local now=$(date +%s) p left=90 done=0 plan=0 avg rem eta note=""
  for p in A B C; do
    if [ "${PH_DONE[$p]}" -gt 0 ]; then avg=$(( PH_SECS[$p] / PH_DONE[$p] )); else avg=${AVG_GUESS[$p]}; fi
    rem=$(( PH_PLAN[$p] - PH_DONE[$p] )); [ "$rem" -lt 0 ] && rem=0
    left=$(( left + rem * avg )); done=$(( done + PH_DONE[$p] )); plan=$(( plan + PH_PLAN[$p] ))
  done
  local pct=100; [ "$plan" -gt 0 ] && pct=$(( 100 * done / plan ))
  eta=$(( now + left ))
  if [ "$eta" -gt "$END" ]; then eta=$END; left=$(( END - now )); note=" - the ${HOURS} h limit will be reached before all runs finish"; fi
  local line="progress ${pct}% (${done}/${plan} runs) | elapsed $(hm $((now-START))) | remaining ~$(hm $left) | expected finish $(date -d @$eta '+%H:%M (%d/%m)')${note} | now: $1"
  log "$line"
  { echo "last update $(date '+%F %T')"; echo "$line"; echo "results in $OUT"; } > "$STATUS"
}
finish_run() {   # $1 = phase, $2 = start time of the run, $3 = label
  sleep 20
  PH_DONE[$1]=$(( PH_DONE[$1] + 1 )); PH_SECS[$1]=$(( PH_SECS[$1] + $(date +%s) - $2 ))
  progress "finished $3"
}
stop_now() {
  if [ "$(date +%s)" -ge "$END" ]; then log "deadline reached"; return 0; fi
  if [ -f ~/pqc/STOP_REVISION ]; then log "STOP_REVISION found"; return 0; fi
  return 1
}

# ---------------------------------------------------------------- embedded helper files
cat > "$OUT/tools/bench_night.mjs" <<'BENCH_NIGHT_EOF_R1'
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
BENCH_NIGHT_EOF_R1
cat > "$OUT/tools/negctl.mjs" <<'NEGCTL_EOF_R1'
// negctl.mjs - negative controls: does the network reject transactions whose signatures are wrong?
//
// Usage: node negctl.mjs                   (env: FABRIC_SAMPLES, COND, OUT_JSON)
//        NEGCTL_SELFTEST=1 node negctl.mjs (offline check of the transaction surgery; no network needed)
//
// Each test endorses one AnchorAlert through the gateway of peer0.org1 with the offline-signing API
// of fabric-gateway, changes one thing, and records where the network stopped it:
//   T0  control: the prepared transaction is decoded, re-encoded unchanged and re-signed by the
//       client -> expected to commit VALID. Run first and last (T0b).
//   T1  client (envelope) signature with one bit flipped -> expected to be refused by the orderer
//   T2  proposal signature with one bit flipped -> expected to be refused by the endorsing peers
//   T3  org1's endorsement signature with one bit flipped -> expected ENDORSEMENT_POLICY_FAILURE
//   T4  org1's endorsement replaced by one that claims Org1MSP but carries peer0.org2's certificate
//       (issued by the org2 CA) and a valid signature by peer0.org2's key -> ENDORSEMENT_POLICY_FAILURE
//   T5  org1's endorsement signature replaced by a valid ML-DSA signature of the other parameter set
//       (ML-DSA-65 on an ML-DSA-44 network, ML-DSA-44 on an ML-DSA-65 network) from a fresh key: a
//       well-formed signature of the wrong length and key -> ENDORSEMENT_POLICY_FAILURE
//                                                                      (conditions mldsa44, mldsa65)
//   T6  org1's endorsement signature replaced by a valid ECDSA signature made with peer0.org1's
//       classical (subject) key, which the hybrid certificate carries -> ENDORSEMENT_POLICY_FAILURE
//                                                                         (condition hybrid44)
// An endorsement signature covers proposal_response_payload || endorser (Fabric's endorser and
// validator); the client signature covers the envelope payload. ML-DSA signs the message itself
// (the fork does not hash first); ECDSA signs its SHA-256 digest with a low-S signature.
// Every forged signature is checked locally before it is sent, so that a rejection can be
// attributed to the property under test and not to a malformed signature.
import * as grpc from '@grpc/grpc-js';
import { connect, hash, signers } from '@hyperledger/fabric-gateway';
import * as crypto from 'crypto'; import { promises as fs } from 'fs'; import * as path from 'path';
import { createRequire } from 'module';

const requireHere = createRequire(import.meta.url);
// fabric-protos is a dependency of fabric-gateway: resolve it from there, whatever the install layout
const protos = createRequire(requireHere.resolve('@hyperledger/fabric-gateway'))('@hyperledger/fabric-protos');
const { common, peer, msp, gateway: gwp } = protos;

// ---------------------------------------------------------------- helpers
async function readKeys(dir) {        // every private key in a keystore (a hybrid identity has two)
  const keys = [];
  for (const f of (await fs.readdir(dir)).sort()) {
    try { keys.push(crypto.createPrivateKey(await fs.readFile(path.join(dir, f)))); } catch (e) { /* not a key */ }
  }
  if (!keys.length) throw new Error(`no private key in ${dir}`);
  return keys;
}
const isMl = k => String(k.asymmetricKeyType).startsWith('ml-dsa');
const signingKey = keys => keys.find(isMl) ?? keys[0];          // a hybrid identity signs with its ML-DSA key
const firstFile = async dir => path.join(dir, (await fs.readdir(dir)).sort()[0]);

// sign / verify a message as Fabric does for this key type
async function signMsg(key, msg) {
  if (isMl(key)) return new Uint8Array(crypto.sign(null, msg, key));
  if (key.asymmetricKeyType === 'ec') return signers.newPrivateKeySigner(key)(crypto.createHash('sha256').update(msg).digest());
  throw new Error(`unsupported key type ${key.asymmetricKeyType}`);
}
function verifyMsg(pub, msg, sig) {
  try {
    if (String(pub.asymmetricKeyType).startsWith('ml-dsa')) return crypto.verify(null, msg, pub, sig);
    return crypto.verify('sha256', msg, pub, sig);
  } catch (e) { return false; }
}
const flipBit = sig => { const s = Uint8Array.from(sig); s[Math.floor(s.length / 2)] ^= 0x01; return s; };
const concat = (a, b) => { const r = new Uint8Array(a.length + b.length); r.set(a, 0); r.set(b, a.length); return r; };
const eq = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const codeName = c => Object.keys(peer.TxValidationCode).find(k => peer.TxValidationCode[k] === c) ?? String(c);

// ---------------------------------------------------------------- prepared-transaction surgery
// PreparedTransaction{envelope{payload: Payload{header, data: Transaction{actions[0].payload:
//   ChaincodeActionPayload{action: ChaincodeEndorsedAction{proposal_response_payload, endorsements[]}}}}}}
function openTx(bytes) {
  const pt = gwp.PreparedTransaction.deserializeBinary(bytes);
  const env = pt.getEnvelope();
  const payload = common.Payload.deserializeBinary(env.getPayload_asU8());
  const tx = peer.Transaction.deserializeBinary(payload.getData_asU8());
  const actions = tx.getActionsList();
  if (actions.length !== 1) throw new Error(`expected 1 transaction action, found ${actions.length}`);
  const cap = peer.ChaincodeActionPayload.deserializeBinary(actions[0].getPayload_asU8());
  const cea = cap.getAction();
  const ends = cea.getEndorsementsList().map(e => ({ e, id: msp.SerializedIdentity.deserializeBinary(e.getEndorser_asU8()) }));
  return { pt, env, payload, tx, actions, cap, cea, ends, originalPayload: Uint8Array.from(env.getPayload_asU8()) };
}
function closeTx(o) {           // re-encode bottom-up; returns the new (unsigned) PreparedTransaction bytes and payload
  o.cea.setEndorsementsList(o.ends.map(x => x.e));
  o.cap.setAction(o.cea);
  o.actions[0].setPayload(o.cap.serializeBinary());
  o.tx.setActionsList(o.actions);
  o.payload.setData(o.tx.serializeBinary());
  const payloadBytes = o.payload.serializeBinary();
  o.env.setPayload(payloadBytes);
  o.env.setSignature(new Uint8Array(0));
  o.pt.setEnvelope(o.env);
  return { bytes: o.pt.serializeBinary(), payloadBytes };
}
function endorsementOf(o, mspid) {
  const x = o.ends.find(y => y.id.getMspid() === mspid);
  if (!x) throw new Error(`no endorsement by ${mspid} (found: ${o.ends.map(y => y.id.getMspid()).join(',')})`);
  return x;
}
const endorsedMsg = (o, x) => concat(o.cea.getProposalResponsePayload_asU8(), x.e.getEndorser_asU8());

// the four endorsement tamperings; each changes o in place and returns the local checks
function tamperT3(o) {
  const x = endorsementOf(o, 'Org1MSP');
  const before = x.e.getSignature_asU8();
  x.e.setSignature(flipBit(before));
  return { one_bit_changed: before.length === x.e.getSignature_asU8().length && !eq(before, x.e.getSignature_asU8()) };
}
async function tamperT4(o, org2SignKey) {
  const x1 = endorsementOf(o, 'Org1MSP'), x2 = endorsementOf(o, 'Org2MSP');
  const forged = new msp.SerializedIdentity();
  forged.setMspid('Org1MSP'); forged.setIdBytes(x2.id.getIdBytes_asU8());
  const endorserBytes = forged.serializeBinary();
  const msg = concat(o.cea.getProposalResponsePayload_asU8(), endorserBytes);
  const sig = await signMsg(org2SignKey, msg);
  x1.e.setEndorser(endorserBytes); x1.e.setSignature(sig); x1.id = forged;
  return { forged_signature_valid_for_org2_key: verifyMsg(crypto.createPublicKey(org2SignKey), msg, sig),
           forged_identity_claims_org1_with_org2_certificate: forged.getMspid() === 'Org1MSP' && eq(forged.getIdBytes_asU8(), x2.id.getIdBytes_asU8()) };
}
function tamperT5(o, otherAlg) {
  const x = endorsementOf(o, 'Org1MSP');
  const msg = endorsedMsg(o, x);
  const { publicKey, privateKey } = crypto.generateKeyPairSync(otherAlg);
  const sig = new Uint8Array(crypto.sign(null, msg, privateKey));
  const orig = x.e.getSignature_asU8().length;
  x.e.setSignature(sig);
  return { checks: { substitute_signature_valid_for_its_own_key: crypto.verify(null, msg, publicKey, sig),
                     substitute_signature_length_differs: sig.length !== orig },
           substitute_signature_bytes: sig.length, original_signature_bytes: orig };
}
async function tamperT6(o, p1Keys, p1Cert) {
  const x = endorsementOf(o, 'Org1MSP');
  const msg = endorsedMsg(o, x);
  const ec = p1Keys.find(k => k.asymmetricKeyType === 'ec');
  if (!ec) throw new Error('no classical (EC) key in the peer0.org1 keystore');
  const sig = await signMsg(ec, msg);
  // the classical key must be the certificate's subject key, and the signature must verify with it
  const certPub = new crypto.X509Certificate(p1Cert).publicKey;
  const checks = {
    ec_key_is_certificate_subject_key: eq(certPub.export({ type: 'spki', format: 'der' }), crypto.createPublicKey(ec).export({ type: 'spki', format: 'der' })),
    ecdsa_signature_valid_for_subject_key: verifyMsg(certPub, msg, sig),
    endorser_bytes_are_peer0_org1_certificate: eq(x.id.getIdBytes_asU8(), p1Cert),
  };
  x.e.setSignature(sig);
  return checks;
}

// ================================================================ offline self-test
if (process.env.NEGCTL_SELFTEST) {
  const fails = [];
  const ok = (cond, what) => { if (!cond) fails.push(what); };
  const rnd = n => Uint8Array.from(crypto.randomBytes(n));
  for (const alg of ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'ec', 'hybrid']) {
    const gen = a => a === 'ec' ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey : crypto.generateKeyPairSync(a).privateKey;
    const sigAlg = alg === 'hybrid' ? 'ml-dsa-44' : alg;
    const k1 = gen(sigAlg), k2 = gen(sigAlg);
    // a self-signed classical certificate stands in for peer0.org1's hybrid certificate in T6
    const cert1 = Buffer.from(`-----BEGIN CERTIFICATE-----\nfake-${alg}-org1\n-----END CERTIFICATE-----\n`);
    const cert2 = Buffer.from(`-----BEGIN CERTIFICATE-----\nfake-${alg}-org2\n-----END CERTIFICATE-----\n`);
    const prp = rnd(700);
    const mkEnd = async (mspid, cert, key) => {
      const id = new msp.SerializedIdentity(); id.setMspid(mspid); id.setIdBytes(cert);
      const e = new peer.Endorsement(); e.setEndorser(id.serializeBinary());
      e.setSignature(await signMsg(key, concat(prp, id.serializeBinary()))); return e;
    };
    const cea = new peer.ChaincodeEndorsedAction(); cea.setProposalResponsePayload(prp);
    cea.setEndorsementsList([await mkEnd('Org1MSP', cert1, k1), await mkEnd('Org2MSP', cert2, k2)]);
    const cap = new peer.ChaincodeActionPayload(); cap.setChaincodeProposalPayload(rnd(300)); cap.setAction(cea);
    const ta = new peer.TransactionAction(); ta.setHeader(rnd(900)); ta.setPayload(cap.serializeBinary());
    const tx = new peer.Transaction(); tx.setActionsList([ta]);
    const hdr = new common.Header(); hdr.setChannelHeader(rnd(120)); hdr.setSignatureHeader(rnd(1000));
    const pl = new common.Payload(); pl.setHeader(hdr); pl.setData(tx.serializeBinary());
    const env = new common.Envelope(); env.setPayload(pl.serializeBinary());
    const pt = new gwp.PreparedTransaction(); pt.setTransactionId('abc'); pt.setEnvelope(env);
    const bytes = pt.serializeBinary();
    // validator view: verify every endorsement of a re-opened transaction
    const verifyAll = (b, keysByMsp) => { const o = openTx(b); return o.ends.map(x => verifyMsg(crypto.createPublicKey(keysByMsp[x.id.getMspid()]), endorsedMsg(o, x), x.e.getSignature_asU8())); };
    const keys = { Org1MSP: k1, Org2MSP: k2 };
    // T0: unchanged round trip is byte-identical and still verifies
    { const o = openTx(bytes); const c = closeTx(o); ok(eq(c.payloadBytes, env.getPayload_asU8()), `${alg} T0 payload not byte-identical`);
      ok(verifyAll(c.bytes, keys).every(Boolean), `${alg} T0 endorsements do not verify`); ok(openTx(c.bytes).pt.getTransactionId() === 'abc', `${alg} T0 txid lost`); }
    // T3
    { const o = openTx(bytes); const ch = tamperT3(o); const c = closeTx(o); const v = verifyAll(c.bytes, keys);
      ok(ch.one_bit_changed && v[0] === false && v[1] === true, `${alg} T3 wrong (${JSON.stringify(ch)} ${v})`); }
    // T4: the forged endorsement claims Org1MSP, carries org2's cert, verifies with org2's key only
    { const o = openTx(bytes); const ch = await tamperT4(o, k2); const c = closeTx(o); const o2 = openTx(c.bytes);
      const f = o2.ends[0]; ok(f.id.getMspid() === 'Org1MSP' && eq(f.id.getIdBytes_asU8(), cert2), `${alg} T4 identity wrong`);
      ok(verifyMsg(crypto.createPublicKey(k2), endorsedMsg(o2, f), f.e.getSignature_asU8()), `${alg} T4 forged sig invalid for org2 key`);
      ok(!verifyMsg(crypto.createPublicKey(k1), endorsedMsg(o2, f), f.e.getSignature_asU8()), `${alg} T4 forged sig valid for org1 key`);
      ok(Object.values(ch).every(v => v === true), `${alg} T4 checks ${JSON.stringify(ch)}`); ok(o2.ends.length === 2, `${alg} T4 endorsement count`); }
    // T5 (ML-DSA conditions)
    if (alg === 'ml-dsa-44' || alg === 'ml-dsa-65') {
      const o = openTx(bytes); const t = tamperT5(o, alg === 'ml-dsa-44' ? 'ml-dsa-65' : 'ml-dsa-44'); const c = closeTx(o);
      ok(Object.values(t.checks).every(v => v === true), `${alg} T5 checks ${JSON.stringify(t.checks)}`);
      ok(verifyAll(c.bytes, keys)[0] === false, `${alg} T5 substitute verifies under org1 key`);
      ok(t.original_signature_bytes === (alg === 'ml-dsa-44' ? 2420 : 3309), `${alg} T5 original length ${t.original_signature_bytes}`);
    }
    // T6 (hybrid): a real classical certificate is needed for the subject-key check
    if (alg === 'hybrid') {
      const ec = gen('ec');
      const selfCert = await selfSignedEcCert(ec);
      if (!selfCert) { console.error('selftest: openssl not available, T6 subject-key check skipped'); }
      else {
        // rebuild org1's endorsement around the real certificate (ML-DSA signature as on a hybrid network)
        const o = openTx(bytes); const x = endorsementOf(o, 'Org1MSP');
        const id = new msp.SerializedIdentity(); id.setMspid('Org1MSP'); id.setIdBytes(selfCert);
        x.e.setEndorser(id.serializeBinary()); x.id = id; x.e.setSignature(await signMsg(k1, endorsedMsg(o, x)));
        const ch = await tamperT6(o, [ec, k1], selfCert); const c = closeTx(o); const o2 = openTx(c.bytes);
        ok(Object.values(ch).every(v => v === true), `hybrid T6 checks ${JSON.stringify(ch)}`);
        ok(!verifyMsg(crypto.createPublicKey(k1), endorsedMsg(o2, o2.ends[0]), o2.ends[0].e.getSignature_asU8()), 'hybrid T6 ECDSA sig verifies as ML-DSA');
      }
    }
    // client signature over the re-encoded payload, as resigned() does
    { const o = openTx(bytes); tamperT3(o); const c = closeTx(o);
      const ck = alg === 'ec' ? gen('ec') : gen(sigAlg); const digest = alg === 'ec' ? crypto.createHash('sha256').update(c.payloadBytes).digest() : c.payloadBytes;
      const sig = alg === 'ec' ? await signers.newPrivateKeySigner(ck)(digest) : new Uint8Array(crypto.sign(null, digest, ck));
      ok(verifyMsg(crypto.createPublicKey(ck), c.payloadBytes, sig), `${alg} client signature over payload does not verify`);
      ok(!verifyMsg(crypto.createPublicKey(ck), c.payloadBytes, flipBit(sig)), `${alg} flipped client signature verifies`); }
  }
  ok(codeName(10) === 'ENDORSEMENT_POLICY_FAILURE' && codeName(0) === 'VALID', 'validation code names');
  console.log(fails.length ? `SELFTEST FAILED: ${fails.join('; ')}` : 'SELFTEST OK');
  process.exit(fails.length ? 1 : 0);
}

async function selfSignedEcCert(ecKey) {      // only for the self-test
  const { execFileSync } = await import('child_process');
  const os = await import('os');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'negctl-'));
  try {
    await fs.writeFile(path.join(dir, 'k.pem'), ecKey.export({ type: 'pkcs8', format: 'pem' }));
    execFileSync('openssl', ['req', '-new', '-x509', '-key', path.join(dir, 'k.pem'), '-subj', '/CN=selftest', '-days', '1', '-out', path.join(dir, 'c.pem')], { stdio: 'ignore' });
    return await fs.readFile(path.join(dir, 'c.pem'));
  } catch (e) { return null; } finally { await fs.rm(dir, { recursive: true, force: true }); }
}

// ================================================================ network tests
const COND = process.env.COND || '';
const CH = 'mychannel', CC = 'cityanchor';
const ROOT = process.env.FABRIC_SAMPLES || path.resolve(process.env.HOME, 'fabric-samples');
const ORGS = path.join(ROOT, 'test-network/organizations/peerOrganizations');
const O1 = path.join(ORGS, 'org1.example.com'), O2 = path.join(ORGS, 'org2.example.com');

const userMsp = path.join(O1, 'users/User1@org1.example.com/msp');
const clientKey = signingKey(await readKeys(path.join(userMsp, 'keystore')));
const clientCert = await fs.readFile(await firstFile(path.join(userMsp, 'signcerts')));
const clientSigner = isMl(clientKey) ? (m => Promise.resolve(new Uint8Array(crypto.sign(null, m, clientKey))))
                                     : signers.newPrivateKeySigner(clientKey);
const digestOf = payload => isMl(clientKey) ? payload : new Uint8Array(crypto.createHash('sha256').update(payload).digest());

const tls = await fs.readFile(path.join(O1, 'peers/peer0.org1.example.com/tls/ca.crt'));
const client = new grpc.Client('localhost:7051', grpc.credentials.createSsl(tls), { 'grpc.ssl_target_name_override': 'peer0.org1.example.com' });
const gw = connect({
  client,
  identity: { mspId: 'Org1MSP', credentials: clientCert },
  signer: clientSigner,
  ...(isMl(clientKey) ? { hash: hash.none } : {}),
  evaluateOptions: () => ({ deadline: Date.now() + 60000 }),
  endorseOptions: () => ({ deadline: Date.now() + 60000 }),
  submitOptions: () => ({ deadline: Date.now() + 60000 }),
  commitStatusOptions: () => ({ deadline: Date.now() + 120000 }),
});
const contract = gw.getNetwork(CH).getContract(CC);

const p1Keys = await readKeys(path.join(O1, 'peers/peer0.org1.example.com/msp/keystore'));
const p2Keys = await readKeys(path.join(O2, 'peers/peer0.org2.example.com/msp/keystore'));
const p1Cert = await fs.readFile(await firstFile(path.join(O1, 'peers/peer0.org1.example.com/msp/signcerts')));

const results = [];
let seq = 0;
const newProposal = test => contract.newProposal('AnchorAlert', {
  arguments: [`neg-${COND}-${test}-${Date.now()}-${seq++}`, 'Transport', 'dt8', crypto.createHash('sha256').update(test).digest('hex'), String(Date.now())],
});
const errText = e => {
  const parts = [e?.message ?? String(e)];
  for (const d of e?.details ?? []) parts.push(`[${d.mspId ?? ''}@${d.address ?? ''}] ${d.message ?? ''}`);
  return parts.join(' | ').slice(0, 1500);
};

async function runTest(test, description, expected, build) {
  const r = { cond: COND, test, description, expected, stage: null, code: null, code_name: null, error: null, checks: {} };
  const t0 = performance.now();
  try {
    const signed = await build(r);       // a signed Transaction, or null when the test ended earlier
    if (signed) {
      let submitted = null;
      try { submitted = await signed.submit(); }
      catch (e) { r.stage = 'submit'; r.error = errText(e); }
      if (submitted) {
        const st = await submitted.getStatus();
        r.stage = 'commit'; r.code = st.code; r.code_name = codeName(st.code); r.block = String(st.blockNumber ?? '');
      }
    }
  } catch (e) { if (!r.stage) { r.stage = 'driver'; r.error = errText(e); } }
  r.ms = Math.round(performance.now() - t0);
  const checksOk = Object.values(r.checks).every(v => v === true);
  if (expected === 'VALID') r.pass = r.stage === 'commit' && r.code === peer.TxValidationCode.VALID && r.checks.endorsements === true;
  else if (expected === 'refused at submit (orderer)') r.pass = r.stage === 'submit' && /FORBIDDEN|BAD_REQUEST/.test(r.error ?? '');
  else if (expected === 'refused at endorsement') r.pass = r.stage === 'endorse' && /access denied|signature|creator|identity/i.test(r.error ?? '');
  else r.pass = r.stage === 'commit' && r.code_name === expected && checksOk;
  r.committed_valid = r.stage === 'commit' && r.code === peer.TxValidationCode.VALID;
  results.push(r);
  console.error(`${test}: stage=${r.stage} code=${r.code_name ?? '-'} pass=${r.pass}${r.error ? ' error=' + r.error.slice(0, 200) : ''}`);
}

async function endorsed(r, test) {      // endorse normally; return the opened prepared transaction
  try { const t = await newProposal(test).endorse(); return openTx(t.getBytes()); }
  catch (e) { r.stage = 'endorse'; r.error = errText(e); throw e; }
}
async function resigned(o, sigTransform = s => s) {
  const { bytes, payloadBytes } = closeTx(o);
  const sig = await clientSigner(digestOf(payloadBytes));
  return gw.newSignedTransaction(bytes, sigTransform(sig));
}

async function T0(name) {
  await runTest(name, 'control: decoded, re-encoded unchanged and re-signed by the client', 'VALID', async r => {
    const o = await endorsed(r, name);
    r.checks.endorsements = o.ends.length === 2;
    const o2 = openTx(o.pt.serializeBinary());
    const { payloadBytes } = closeTx(o2);
    r.checks.reencoding_byte_identical = eq(o.originalPayload, payloadBytes);      // informational
    return resigned(openTx(o.pt.serializeBinary()));
  });
}

await T0('T0');
await runTest('T1', 'client (envelope) signature with one bit flipped', 'refused at submit (orderer)', async r => {
  const o = await endorsed(r, 'T1');
  return resigned(o, flipBit);
});
await runTest('T2', 'proposal signature with one bit flipped', 'refused at endorsement', async r => {
  const unsigned = newProposal('T2');
  const sig = await clientSigner(unsigned.getDigest());
  try { await gw.newSignedProposal(unsigned.getBytes(), flipBit(sig)).endorse(); }
  catch (e) { r.stage = 'endorse'; r.error = errText(e); return null; }
  r.stage = 'endorsed'; return null;      // the endorsement was accepted: the test fails
});
await runTest('T3', "org1's endorsement signature with one bit flipped", 'ENDORSEMENT_POLICY_FAILURE', async r => {
  const o = await endorsed(r, 'T3');
  Object.assign(r.checks, tamperT3(o));
  return resigned(o);
});
await runTest('T4', "endorsement claiming Org1MSP with peer0.org2's certificate (org2 CA) and a valid org2 signature",
  'ENDORSEMENT_POLICY_FAILURE', async r => {
  const o = await endorsed(r, 'T4');
  Object.assign(r.checks, await tamperT4(o, signingKey(p2Keys)));
  return resigned(o);
});
if (COND === 'mldsa44' || COND === 'mldsa65') {
  const other = COND === 'mldsa44' ? 'ml-dsa-65' : 'ml-dsa-44';
  await runTest('T5', `org1's endorsement signature replaced by a valid ${other} signature from a fresh key`,
    'ENDORSEMENT_POLICY_FAILURE', async r => {
    const o = await endorsed(r, 'T5');
    const t = tamperT5(o, other);
    Object.assign(r.checks, t.checks); r.substitute_signature_bytes = t.substitute_signature_bytes; r.original_signature_bytes = t.original_signature_bytes;
    return resigned(o);
  });
}
if (COND === 'hybrid44') {
  await runTest('T6', "org1's endorsement signature replaced by a valid ECDSA signature with peer0.org1's classical (subject) key",
    'ENDORSEMENT_POLICY_FAILURE', async r => {
    const o = await endorsed(r, 'T6');
    Object.assign(r.checks, await tamperT6(o, p1Keys, p1Cert));
    return resigned(o);
  });
}
await T0('T0b');

const summary = { cond: COND, client_key: clientKey.asymmetricKeyType, endorser_keys_org1: p1Keys.map(k => k.asymmetricKeyType),
  tests: results.length, passed: results.filter(r => r.pass).length, results };
console.log(JSON.stringify(summary, null, 1));
await fs.writeFile(process.env.OUT_JSON || 'negctl.json', JSON.stringify(summary, null, 1));
gw.close(); client.close();
NEGCTL_EOF_R1
cat > "$OUT/tools/tlshello.py" <<'TLSHELLO_EOF_R1'
"""TLS key-exchange groups offered and selected on every new TCP connection of a packet capture.

Usage: python3 tlshello.py capture.pcap [--names names.txt] [--json out.json]

Reads a classic pcap file (tcpdump -w; link types Ethernet, Linux cooked v1 and v2, raw IPv4),
reassembles the first bytes of each direction of every IPv4 TCP connection whose SYN is in the
capture, and parses the TLS handshake records that open it:
  ClientHello  supported_groups and key_share groups offered
  ServerHello  key_share group selected, negotiated version (supported_versions), and whether the
               server first answered with a HelloRetryRequest
Connections that do not start with a TLS handshake (plain HTTP/2, chaincode traffic) are listed as
"not TLS". --names gives "IP name" lines (from docker network inspect) so that endpoints are named.
Dependency-free (standard library only).
"""
import json
import struct
import sys
from collections import defaultdict

GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001d: "X25519", 0x001e: "X448",
          0x0100: "ffdhe2048", 0x11eb: "SecP256r1MLKEM768", 0x11ec: "X25519MLKEM768", 0x11ed: "SecP384r1MLKEM1024",
          0x6399: "X25519Kyber768Draft00", 0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024"}
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
MAX_STREAM = 16384          # bytes per direction kept for parsing


def gname(g):
    return GROUPS.get(g, f"0x{g:04x}")


def read_pcap(path):
    """Yield (linktype, packet bytes) from a classic pcap file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        else:
            raise ValueError("not a classic pcap file (pcapng is not supported; use tcpdump -w)")
        linktype = struct.unpack(e + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _, _, incl, _ = struct.unpack(e + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield linktype, data


def ipv4_of(linktype, pkt):
    """Return the IPv4 packet inside a captured frame, or None."""
    if linktype == 1:                                   # Ethernet (with optional 802.1Q tags)
        off, et = 12, None
        while off + 2 <= len(pkt):
            et = struct.unpack(">H", pkt[off:off + 2])[0]
            if et in (0x8100, 0x88a8):
                off += 4
                continue
            off += 2
            break
        return pkt[off:] if et == 0x0800 else None
    if linktype == 113:                                 # Linux cooked v1: protocol at bytes 14-15
        return pkt[16:] if len(pkt) >= 16 and struct.unpack(">H", pkt[14:16])[0] == 0x0800 else None
    if linktype == 276:                                 # Linux cooked v2: protocol at bytes 0-1
        return pkt[20:] if len(pkt) >= 20 and struct.unpack(">H", pkt[0:2])[0] == 0x0800 else None
    if linktype in (101, 228):                          # raw IP / raw IPv4
        return pkt if pkt and pkt[0] >> 4 == 4 else None
    return None


def tcp_segments(path):
    """Yield (src, sport, dst, dport, seq, flags, payload) for every IPv4 TCP segment."""
    for lt, pkt in read_pcap(path):
        ip = ipv4_of(lt, pkt)
        if not ip or len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        if total and total < len(ip):
            ip = ip[:total]                             # drop link-layer padding; 0 = offloaded super-packet
        frag = struct.unpack(">H", ip[6:8])[0]
        if frag & 0x1FFF:
            continue                                    # a later fragment carries no TCP header
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        yield src, sport, dst, dport, seq, flags, tcp[doff:]


def streams(path):
    """Reassemble the first MAX_STREAM bytes of each direction of connections whose SYN was captured."""
    isn = {}                                            # (src, sport, dst, dport) -> initial sequence number
    segs = defaultdict(dict)                            # direction -> {relative offset: payload}
    for src, sport, dst, dport, seq, flags, payload in tcp_segments(path):
        k = (src, sport, dst, dport)
        if flags & 0x02:                                # SYN (and SYN-ACK): the first data byte is isn + 1
            isn.setdefault(k, seq)
            continue
        if k not in isn or not payload:
            continue
        off = (seq - isn[k] - 1) & 0xFFFFFFFF
        if off >= MAX_STREAM:
            continue
        if off not in segs[k] or len(payload) > len(segs[k][off]):
            segs[k][off] = payload
    out = {}
    for k in isn:
        buf, pos = bytearray(), 0
        for off in sorted(segs.get(k, {})):
            p = segs[k][off]
            if off > pos:
                break                                   # gap: keep the contiguous prefix only
            if off + len(p) > pos:
                buf += p[pos - off:]
                pos = off + len(p)
            if pos >= MAX_STREAM:
                break
        out[k] = bytes(buf[:MAX_STREAM])
    return out


def handshake_messages(stream):
    """Return [(type, body)] from the leading TLS handshake records of a stream, or None if not TLS."""
    i, hs = 0, bytearray()
    if len(stream) < 5 or stream[0] != 22 or stream[1] != 3:
        return None
    while i + 5 <= len(stream) and stream[i] in (20, 22):  # handshake records; skip ChangeCipherSpec
        ln = struct.unpack(">H", stream[i + 3:i + 5])[0]
        if stream[i] == 22:
            hs += stream[i + 5:i + 5 + ln]
        i += 5 + ln
    msgs, j = [], 0
    while j + 4 <= len(hs):
        t = hs[j]
        ln = int.from_bytes(hs[j + 1:j + 4], "big")
        if j + 4 + ln > len(hs):
            msgs.append((t, None))                      # truncated (capture or reassembly limit)
            break
        msgs.append((t, bytes(hs[j + 4:j + 4 + ln])))
        j += 4 + ln
    return msgs


def extensions(body, start):
    """Parse the extension block that starts at body[start]; return {type: data}."""
    ext = {}
    if start + 2 > len(body):
        return ext
    end = start + 2 + struct.unpack(">H", body[start:start + 2])[0]
    i = start + 2
    while i + 4 <= min(end, len(body)):
        et, ln = struct.unpack(">HH", body[i:i + 4])
        ext[et] = body[i + 4:i + 4 + ln]
        i += 4 + ln
    return ext


def parse_client_hello(b):
    i = 2 + 32                                          # legacy_version, random
    i += 1 + b[i]                                       # session id
    i += 2 + struct.unpack(">H", b[i:i + 2])[0]         # cipher suites
    i += 1 + b[i]                                       # compression methods
    ext = extensions(b, i)
    r = {"sni": None, "supported_groups": [], "key_share_groups": [], "key_share_bytes": {}}
    if 0 in ext and len(ext[0]) > 5:
        r["sni"] = ext[0][5:].decode("ascii", "replace")
    if 10 in ext:
        d = ext[10]
        r["supported_groups"] = [gname(struct.unpack(">H", d[k:k + 2])[0]) for k in range(2, 2 + struct.unpack(">H", d[:2])[0], 2)]
    if 51 in ext:
        d, k = ext[51], 2
        while k + 4 <= len(d):
            g, ln = struct.unpack(">HH", d[k:k + 4])
            r["key_share_groups"].append(gname(g))
            r["key_share_bytes"][gname(g)] = ln
            k += 4 + ln
    if 43 in ext:
        d = ext[43]
        r["versions"] = [f"0x{struct.unpack('>H', d[k:k + 2])[0]:04x}" for k in range(1, 1 + d[0], 2)]
    return r


def parse_server_hello(b):
    random = b[2:34]                                    # after legacy_version
    i = 34
    i += 1 + b[i]                                       # session id
    cipher = struct.unpack(">H", b[i:i + 2])[0]
    i += 2 + 1                                          # cipher suite, compression method
    ext = extensions(b, i)
    r = {"hello_retry_request": random == HRR_RANDOM, "cipher_suite": f"0x{cipher:04x}", "group": None, "key_share_bytes": None, "version": "0x0303"}
    if 43 in ext and len(ext[43]) == 2:
        r["version"] = f"0x{struct.unpack('>H', ext[43])[0]:04x}"
    if 51 in ext and len(ext[51]) >= 2:
        r["group"] = gname(struct.unpack(">H", ext[51][:2])[0])
        if len(ext[51]) >= 4 and not r["hello_retry_request"]:
            r["key_share_bytes"] = struct.unpack(">H", ext[51][2:4])[0]
    return r


def analyse(pcap, names=None):
    names = names or {}
    st = streams(pcap)
    conns = []
    for (src, sport, dst, dport), cstream in st.items():
        rev = (dst, dport, src, sport)
        if rev not in st:
            continue                                    # one direction only: no SYN-ACK seen
        # the client is the side that sent the first SYN; the SYN-ACK side also has an ISN, so keep the
        # direction whose first message is a ClientHello (or, for non-TLS, the lower port as server)
        msgs = handshake_messages(cstream)
        if not msgs or msgs[0][0] != 1:
            continue                                    # this direction is not the client of a TLS handshake
        c = {"client": names.get(src, src), "client_ip": src, "server": names.get(dst, dst), "server_ip": dst,
             "server_port": dport}
        if msgs[0][1] is None:
            c["error"] = "ClientHello truncated"
        else:
            try:
                c.update({"client_hello": parse_client_hello(msgs[0][1])})
            except Exception as e:  # noqa: BLE001
                c["error"] = f"ClientHello parse: {e}"
        smsgs = handshake_messages(st[rev]) or []
        sh = [m for m in smsgs if m[0] == 2]
        if sh and sh[0][1] is not None:
            try:
                first = parse_server_hello(sh[0][1])
                c["server_hello"] = first
                if first["hello_retry_request"]:
                    c["hrr_group"] = first["group"]
                    # after a HelloRetryRequest the real ServerHello follows in the same direction
                    later = [m for m in sh[1:] if m[1] is not None]
                    if later:
                        c["server_hello"] = parse_server_hello(later[0][1])
                c["selected_group"] = c["server_hello"]["group"]
            except Exception as e:  # noqa: BLE001
                c["error"] = f"ServerHello parse: {e}"
        else:
            c["selected_group"] = None
            c.setdefault("error", "no ServerHello in the capture")
        conns.append(c)
    conns.sort(key=lambda c: (c["client"], c["server"], c["server_port"]))
    summary = defaultdict(lambda: defaultdict(int))
    for c in conns:
        summary[f"{c['client']} -> {c['server']}:{c['server_port']}"][str(c.get("selected_group"))] += 1
    tcp_conns = sum(1 for k in st if (k[2], k[3], k[0], k[1]) in st) // 2
    return {"file": pcap, "tcp_connections_with_handshake_seen": tcp_conns, "tls_connections": len(conns),
            "by_endpoint_pair": {k: dict(v) for k, v in sorted(summary.items())}, "connections": conns}


def main(argv):
    out = names_file = None
    args = list(argv)
    if "--json" in args:
        out = args[args.index("--json") + 1]
        del args[args.index("--json"):args.index("--json") + 2]
    if "--names" in args:
        names_file = args[args.index("--names") + 1]
        del args[args.index("--names"):args.index("--names") + 2]
    names = {}
    if names_file:
        for line in open(names_file):
            p = line.split()
            if len(p) >= 2:
                names[p[0]] = p[1]
    res = analyse(args[0], names)
    for k, v in res["by_endpoint_pair"].items():
        print(f"{k}: {v}")
    print(f"TLS connections: {res['tls_connections']} (TCP connections with SYN and SYN-ACK: {res['tcp_connections_with_handshake_seen']})")
    if out:
        with open(out, "w") as f:
            json.dump(res, f, indent=1)
    return res


if __name__ == "__main__":
    main(sys.argv[1:])
TLSHELLO_EOF_R1
cat > "$OUT/tools/blockcomp.py" <<'BLOCKCOMP_EOF_R1'
"""Compression of a Fabric peer block file one block at a time, with and without a dictionary.

Usage: python3 blockcomp.py blockfile_000000 [more block files of the same ledger]
                            --certs cert1.pem [cert2.pem ...] [--json out.json]

The peer stores each block as [varint length][serialized block]. A block is the unit a peer reads
back during validation, state recovery and block delivery, so this tool compresses every block on
its own (configuration-only blocks are left out, as in the whole-file estimate of the paper):
  gzip6        gzip level 6 (Python standard library), per block
  zstd3        zstd level 3, per block, no dictionary
  zstd3_certs  zstd level 3, per block, with a raw-content dictionary made of the PEM certificates
               given with --certs (the identities that every transaction repeats); every block is
               decompressed again and compared with the original
  zstd3_trained  zstd level 3 with a dictionary trained (zstd --train) on the first half of the
               transaction blocks, measured on the second half only, next to zstd3 on the same half
It also reports the whole-file zstd 3 of the same transaction blocks for reference, and how often
each certificate occurs in them. Requires the zstd command.
"""
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]
        r |= (c & 0x7F) << s
        i += 1
        if not c & 0x80:
            return r, i
        s += 7


def fields(b):
    i, n = 0, len(b)
    while i < n:
        key, i = varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            ln, i = varint(b, i)
            v = b[i:i + ln]
            i += ln
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        else:
            raise ValueError(f"wire type {wt}")
        yield f, wt, v


def endorser_txs(blk):
    """Number of ENDORSER_TRANSACTION envelopes in a serialized block (Fabric block_serialization.go)."""
    i = 0
    _, i = varint(blk, i)                               # block number
    ln, i = varint(blk, i)
    i += ln                                             # data hash
    ln, i = varint(blk, i)
    i += ln                                             # previous hash
    ntx, i = varint(blk, i)
    n = 0
    for _ in range(ntx):
        ln, i = varint(blk, i)
        env = blk[i:i + ln]
        i += ln
        for f, wt, payload in fields(env):
            if f == 1 and wt == 2:
                for pf, pwt, hdr in fields(payload):
                    if pf == 1 and pwt == 2:
                        for hf, hwt, ch in fields(hdr):
                            if hf == 1 and hwt == 2:
                                for cf, cwt, cv in fields(ch):
                                    if cf == 1 and cwt == 0 and cv == 3:
                                        n += 1
    return n


def blocks_of(paths):
    out = []
    for p in paths:
        b = open(p, "rb").read()
        i = 0
        while i < len(b):
            ln, j = varint(b, i)
            out.append(b[j:j + ln])
            i = j + ln
    return out


def zstd(data, *extra):
    return subprocess.run(["zstd", "-3", "-c", "-q", *extra], input=data, capture_output=True, check=True).stdout


def unzstd(data, *extra):
    return subprocess.run(["zstd", "-d", "-c", "-q", *extra], input=data, capture_output=True, check=True).stdout


def main(argv):
    args = list(argv)
    out = None
    if "--json" in args:
        out = args[args.index("--json") + 1]
        del args[args.index("--json"):args.index("--json") + 2]
    certs = []
    if "--certs" in args:
        k = args.index("--certs")
        certs = args[k + 1:]
        args = args[:k]
    files = args
    if not shutil.which("zstd"):
        raise SystemExit("the zstd command is required")
    blocks = blocks_of(files)
    txb = [(b, endorser_txs(b)) for b in blocks]
    txb = [(b, n) for b, n in txb if n > 0]
    ntx = sum(n for _, n in txb)
    if not txb:
        raise SystemExit("no transaction blocks")
    raw = sum(len(b) for b, _ in txb)
    res = {"files": [os.path.basename(f) for f in files], "blocks_total": len(blocks), "transaction_blocks": len(txb),
           "transactions": ntx, "raw_bytes": raw, "zstd_version": subprocess.run(["zstd", "-V"], capture_output=True, text=True).stdout.strip()}

    # certificate dictionary (raw content: the PEM files as they appear in the identities)
    pems, seen = [], set()
    for c in certs:
        d = open(c, "rb").read()
        h = hashlib.sha256(d).hexdigest()
        if h not in seen:
            seen.add(h)
            pems.append((os.path.basename(c), d))
    allraw = b"".join(b for b, _ in txb)
    res["certificates"] = [{"file": n, "bytes": len(d), "occurrences_in_transaction_blocks": allraw.count(d)} for n, d in pems]
    tmp = tempfile.mkdtemp(prefix="blockcomp-")
    try:
        dict_path = os.path.join(tmp, "certs.dict")
        with open(dict_path, "wb") as f:
            f.write(b"".join(d for _, d in pems))
        res["cert_dictionary_bytes"] = os.path.getsize(dict_path)

        g = z = zd = 0
        for b, _ in txb:
            g += len(gzip.compress(b, 6))
            z += len(zstd(b))
            if pems:
                c = zstd(b, "-D", dict_path)
                if unzstd(c, "-D", dict_path) != b:
                    raise SystemExit("round trip with the certificate dictionary failed")
                zd += len(c)
        per = {"gzip6": g, "zstd3": z}
        if pems:
            per["zstd3_certs"] = zd
        res["per_block"] = {k: {"bytes": v, "saving_pct": round(100 * (1 - v / raw), 1), "bytes_per_tx": round(v / ntx, 1)} for k, v in per.items()}
        res["raw_bytes_per_tx"] = round(raw / ntx, 1)
        whole = len(zstd(allraw))
        res["whole_file_zstd3"] = {"bytes": whole, "saving_pct": round(100 * (1 - whole / raw), 1), "bytes_per_tx": round(whole / ntx, 1)}

        # trained dictionary: train on the first half of the transaction blocks, measure on the second half
        half = len(txb) // 2
        train, test = txb[:half], txb[half:]
        tr = {"train_blocks": len(train), "test_blocks": len(test)}
        if len(train) >= 8:
            sdir = os.path.join(tmp, "samples")
            os.mkdir(sdir)
            for k, (b, _) in enumerate(train):
                with open(os.path.join(sdir, f"b{k:05d}"), "wb") as f:
                    f.write(b)
            tdict = os.path.join(tmp, "trained.dict")
            p = subprocess.run(["zstd", "--train", "-q", "-o", tdict] + [os.path.join(sdir, x) for x in sorted(os.listdir(sdir))],
                               capture_output=True, text=True)
            if p.returncode == 0 and os.path.exists(tdict):
                traw = sum(len(b) for b, _ in test)
                tz = tzd = 0
                for b, _ in test:
                    tz += len(zstd(b))
                    c = zstd(b, "-D", tdict)
                    if unzstd(c, "-D", tdict) != b:
                        raise SystemExit("round trip with the trained dictionary failed")
                    tzd += len(c)
                tr.update({"dictionary_bytes": os.path.getsize(tdict), "test_raw_bytes": traw,
                           "zstd3_bytes": tz, "zstd3_saving_pct": round(100 * (1 - tz / traw), 1),
                           "zstd3_trained_bytes": tzd, "zstd3_trained_saving_pct": round(100 * (1 - tzd / traw), 1)})
            else:
                tr["error"] = (p.stderr or p.stdout).strip()[-400:]
        else:
            tr["error"] = "too few transaction blocks to train a dictionary"
        res["trained_dictionary"] = tr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps(res, indent=1))
    if out:
        with open(out, "w") as f:
            json.dump(res, f, indent=1)
    return res


if __name__ == "__main__":
    main(sys.argv[1:])
BLOCKCOMP_EOF_R1
cat > "$OUT/tools/decode_blockfile.py" <<'DECODE_EOF_R1'
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
DECODE_EOF_R1
cat > "$OUT/tools/summarize_revision.py" <<'SUMMARIZE_EOF_R1'
"""Summary tables of a revision run (revision_run.sh): E1 negative controls, E2 TLS groups,
E3 constrained network, E4 ledger growth, E5 per-block compression.

Usage: python3 summarize_revision.py <results directory>
Standard library only. Means carry 95% confidence intervals from the t distribution.
"""
import csv
import glob
import json
import math
import os
import statistics
import sys

T95 = [None, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145,
       2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]
CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]


def ci(xs):
    """(mean, half width of the 95% CI, n); half width None for n < 2."""
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None, 0
    m = statistics.fmean(xs)
    if len(xs) < 2:
        return m, None, len(xs)
    t = T95[len(xs) - 1] if len(xs) - 1 < len(T95) else 1.96
    return m, t * statistics.stdev(xs) / math.sqrt(len(xs)), len(xs)


def fmt(m, h, d=1):
    if m is None:
        return "-"
    return f"{m:.{d}f}" + (f" ± {h:.{d}f}" if h is not None else "")


def order(conds):
    return sorted(conds, key=lambda c: (CONDS.index(c) if c in CONDS else 99, c))


def table(header, rows):
    w = [max(len(str(x)) for x in col) for col in zip(header, *rows)] if rows else [len(h) for h in header]
    line = lambda r: "  ".join(str(x).ljust(n) for x, n in zip(r, w))
    return "\n".join([line(header), line(["-" * n for n in w])] + [line(r) for r in rows])


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def main(out):
    rows = list(csv.DictReader(open(os.path.join(out, "summary.csv")))) if os.path.exists(os.path.join(out, "summary.csv")) else []
    parts = []

    # ---------------------------------------------------------------- E1
    e1 = {}
    for f in glob.glob(os.path.join(out, "A", "*", "negctl.json")):
        d = json.load(open(f))
        e1[d["cond"]] = d
    if e1:
        tests = ["T0", "T1", "T2", "T3", "T4", "T5", "T6", "T0b"]
        body = []
        for c in order(e1):
            res = {r["test"]: r for r in e1[c]["results"]}
            cells = []
            for t in tests:
                r = res.get(t)
                if not r:
                    cells.append("")
                    continue
                o = r["code_name"] if r["stage"] == "commit" else f"refused@{r['stage']}"
                cells.append(o + ("" if r["pass"] else " (!)"))
            body.append([c] + cells + [f"{e1[c]['passed']}/{e1[c]['tests']}"])
        parts.append("E1 negative controls: where each tampered transaction was stopped ((!) = not as expected)\n"
                     "T0/T0b control (unchanged, re-signed); T1 client signature bit flip; T2 proposal signature bit flip;\n"
                     "T3 org1 endorsement signature bit flip; T4 endorsement claiming Org1MSP with org2's certificate;\n"
                     "T5 other ML-DSA parameter set; T6 valid ECDSA signature by the hybrid certificate's classical key\n"
                     + table(["cond"] + tests + ["as expected"], body))
        notes = []
        for c in order(e1):
            for r in e1[c]["results"]:
                if r["checks"] and not all(v is True for k, v in r["checks"].items() if k != "reencoding_byte_identical"):
                    notes.append(f"  {c} {r['test']}: local checks {r['checks']}")
                if r["test"] == "T0" and r["checks"].get("reencoding_byte_identical") is False:
                    notes.append(f"  {c} T0: re-encoded payload not byte-identical (the re-signed payload was still sent)")
        if notes:
            parts.append("E1 notes\n" + "\n".join(notes))
        errs = [f"  {c} {r['test']}: {r['error'][:300]}" for c in order(e1) for r in e1[c]["results"] if r.get("error")]
        if errs:
            parts.append("E1 refusal messages (first 300 characters)\n" + "\n".join(errs))

    # ---------------------------------------------------------------- E2
    e2 = {}
    for f in glob.glob(os.path.join(out, "A", "*", "tls_groups.json")):
        e2[os.path.basename(os.path.dirname(f))] = json.load(open(f))
    if e2:
        body = []
        for c in order(e2):
            for pair, groups in e2[c]["by_endpoint_pair"].items():
                cl, sv = pair.split(" -> ")
                kind = "node-to-node" if ("example.com" in cl and "example.com" in sv) else ("node-to-chaincode" if "ccaas" in sv else "client/other")
                body.append([c, kind, pair, ", ".join(f"{g} x{n}" for g, n in sorted(groups.items()))])
        body.sort(key=lambda r: (order(list(e2)).index(r[0]), r[1] != "node-to-node", r[2]))
        parts.append("E2 TLS key exchange selected on the connections opened after the peers were restarted\n"
                     + table(["cond", "kind", "client -> server:port", "selected group x connections"], body))

    # ---------------------------------------------------------------- E3
    c_rows = [r for r in rows if r["exp"] == "C"]
    if c_rows:
        body, pair_body = [], []
        for c in order({r["cond"] for r in c_rows}):
            rc = [r for r in c_rows if r["cond"] == c]
            by = {}
            for r in rc:
                by.setdefault(r["rep"], {})[r["net"]] = r
            for net in sorted({r["net"] for r in rc}, key=lambda x: (not x.startswith("none"), x)):
                rr = [r for r in rc if r["net"] == net]
                body.append([c, net, len(rr), fmt(*ci([num(r["tx_per_s"]) for r in rr])[:2]),
                             fmt(*ci([num(r["mean_ms"]) for r in rr])[:2], d=0), fmt(*ci([num(r["p99_ms"]) for r in rr])[:2], d=0),
                             fmt(*ci([num(r["rtt_orderer_ms"]) for r in rr])[:2], d=2), fmt(*ci([num(r["rtt_peer_ms"]) for r in rr])[:2], d=2),
                             fmt(*ci([num(r["rtt_chaincode_ms"]) for r in rr])[:2], d=2),
                             sum(1 for r in rr if r["failed_workers"] not in ("0", ""))])
            # paired table: verified labels only (none with wan or wan_all), and no run with a stopped worker
            by = {}
            for r in rc:
                k = "none" if r["net"] == "none" else ("wan" if r["net"] in ("wan", "wan_all") else None)
                if k and r["failed_workers"] in ("0", ""):
                    by.setdefault(r["rep"], {})[k] = r
            pairs = [(num(v["none"]["tx_per_s"]), num(v["wan"]["tx_per_s"]), v) for v in by.values() if "none" in v and "wan" in v]
            ratios = [w / n for n, w, _ in pairs if n and w]
            lat = [num(v["wan"]["mean_ms"]) / num(v["none"]["mean_ms"]) for _, _, v in pairs if num(v["none"]["mean_ms"])]
            m, h, k = ci(ratios)
            ml, hl, _ = ci(lat)
            slower = sum(1 for n, w, _ in pairs if w < n)
            first_wan = sum(1 for _, _, v in pairs if v["wan"]["pos"] == "1")
            pair_body.append([c, k, fmt(100 * (m - 1) if m else None, 100 * h if h else None), f"{slower}/{k}",
                              fmt(100 * (ml - 1) if ml else None, 100 * hl if hl else None), first_wan])
        parts.append("E3 constrained network: 20 clients, the same network with and without netem (10 ms per node egress to the\n"
                     "other nodes, 100 Mbit/s); throughput tx/s, latency ms, round trips ms (peer0.org1 -> orderer, -> its chaincode)\n"
                     + table(["cond", "net", "n", "tx/s", "mean ms", "p99 ms", "rtt orderer", "rtt peer", "rtt chaincode", "failed"], body))
        parts.append("E3 paired by network (wan relative to none, mean of per-network ratios; pairs with a stopped worker or an\n"
                     "unverified round trip are left out)\n"
                     + table(["cond", "pairs", "throughput change %", "wan slower", "mean latency change %", "wan ran first"], pair_body))

    # ---------------------------------------------------------------- E4
    for f in sorted(glob.glob(os.path.join(out, "B", "*", "ledger_growth.csv"))):
        c = os.path.basename(os.path.dirname(f))
        g = list(csv.DictReader(open(f)))
        b_rows = {r["chunk"]: r for r in rows if r["exp"] == "B" and r["cond"] == c}
        body, prev = [], None
        for r in g:
            a = int(r["alerts"])
            tot, bf = int(r["ledger_total"]), int(r["block_files"])
            inc_t = inc_b = ""
            if prev:
                da = a - int(prev["alerts"])
                if da > 0:
                    inc_t = f"{(tot - int(prev['ledger_total'])) / da:.0f}"
                    inc_b = f"{(bf - int(prev['block_files'])) / da:.0f}"
            br = b_rows.get(r["step"], {})
            body.append([r["step"], a, r["height"], br.get("tx_per_s", ""), f"{tot / 1e6:.1f}", f"{bf / 1e6:.1f}",
                         f"{int(r['block_index']) / 1e6:.1f}", f"{int(r['state_db']) / 1e6:.1f}", f"{int(r['history_db']) / 1e6:.1f}",
                         f"{int(r['other']) / 1e6:.1f}", f"{tot / a:.0f}" if int(r["step"]) > 0 else "", inc_t, inc_b,
                         f"{int(r['peer2_ledger_total']) / 1e6:.1f}" if r["peer2_ledger_total"] else "",
                         f"{int(r['orderer_ledger_total']) / 1e6:.1f}" if r["orderer_ledger_total"] else ""])
            prev = r
        fit = ""
        pts = [(int(r["alerts"]), int(r["ledger_total"]), int(r["block_files"])) for r in g if int(r["step"]) > 0]
        if len(pts) >= 3:
            def ols(xs, ys):
                mx, my = statistics.fmean(xs), statistics.fmean(ys)
                sxx = sum((x - mx) ** 2 for x in xs)
                b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
                ss_res = sum((y - (my + b * (x - mx))) ** 2 for x, y in zip(xs, ys))
                ss_tot = sum((y - my) ** 2 for y in ys)
                return b, 1 - ss_res / ss_tot if ss_tot else 1.0
            bt, rt = ols([p[0] for p in pts], [p[1] for p in pts])
            bb, rb = ols([p[0] for p in pts], [p[2] for p in pts])
            fit = (f"\n  linear fit over steps 1..{len(pts)}: ledger {bt:.0f} B per alert (R^2 {rt:.6f}), "
                   f"block files {bb:.0f} B per alert (R^2 {rb:.6f})")
            tps = [num(b_rows[s]["tx_per_s"]) for s in sorted(b_rows, key=int)]
            if len(tps) >= 2:
                fit += f"\n  throughput per chunk: first {tps[0]:.1f}, last {tps[-1]:.1f}, min {min(tps):.1f}, max {max(tps):.1f} tx/s"
        parts.append(f"E4 ledger growth, {c}, peer0.org1 (MB = 10^6 B; incremental B per alert since the previous step)\n"
                     + table(["step", "alerts", "height", "tx/s", "ledger MB", "block files", "index", "state", "history", "other",
                              "B/alert", "incr total", "incr blocks", "peer2 MB", "orderer MB"], body) + fit)

    # ---------------------------------------------------------------- E5
    e5 = {}
    for f in glob.glob(os.path.join(out, "A", "*", "blockcomp.json")):
        e5[os.path.basename(os.path.dirname(f))] = json.load(open(f))
    if e5:
        body = []
        for c in order(e5):
            d = e5[c]
            p = d["per_block"]
            tr = d.get("trained_dictionary", {})
            body.append([c, d["transactions"], d["transaction_blocks"], d["raw_bytes_per_tx"],
                         f"{p['gzip6']['saving_pct']}%", f"{p['zstd3']['saving_pct']}%",
                         f"{p['zstd3_certs']['saving_pct']}%" if "zstd3_certs" in p else "-",
                         f"{d['whole_file_zstd3']['saving_pct']}%",
                         f"{tr.get('zstd3_saving_pct', '-')}% -> {tr.get('zstd3_trained_saving_pct', '-')}%",
                         " ".join(str(x["occurrences_in_transaction_blocks"]) for x in d.get("certificates", []))])
        parts.append("E5 compression one block at a time (transaction blocks only; savings relative to the stored bytes)\n"
                     + table(["cond", "tx", "blocks", "B/tx stored", "gzip6", "zstd3", "zstd3+cert dict", "whole-file zstd3",
                              "trained dict (2nd half: plain -> dict)", "cert occurrences"], body))

    # ---------------------------------------------------------------- phase A throughput (sanity check against Table 6)
    a_rows = [r for r in rows if r["exp"] == "A"]
    if a_rows:
        parts.append("Phase A benchmark (ledger for E5; compare with Table 6 at 20 clients)\n"
                     + table(["cond", "n_tx", "failed", "tx/s", "mean ms", "p99 ms"],
                             [[r["cond"], r["n_tx"], r["failed_workers"], r["tx_per_s"], r["mean_ms"], r["p99_ms"]] for r in a_rows]))
    print("\n\n".join(parts) if parts else "no results")


if __name__ == "__main__":
    main(sys.argv[1])
SUMMARIZE_EOF_R1
cp "$0" "$OUT/tools/revision_run.sh" 2>/dev/null

echo "exp,cond,rep,net,pos,chunk,concurrency,n_tx,failed_workers,tx_per_s,mean_ms,p50_ms,p95_ms,p99_ms,wall_s,key_type,height_before,height_after,rtt_orderer_ms,rtt_peer_ms,rtt_chaincode_ms" > "$CSV"

# ---------------------------------------------------------------- orderer batch settings (must be the paper's defaults)
batch_line_counts_ok() {
  [ "$(grep -cE '^ *BatchTimeout:' "$CFG")" = 1 ] && [ "$(grep -cE '^ *PreferredMaxBytes:' "$CFG")" = 1 ]
}
set_batch() {   # $1 = PreferredMaxBytes, $2 = BatchTimeout
  MODIFIED=1
  sed -i -E "s/^( *PreferredMaxBytes:).*/\1 $1/; s/^( *BatchTimeout:).*/\1 $2/" "$CFG"
  grep -qE "^ *PreferredMaxBytes: $1\$" "$CFG" && grep -qE "^ *BatchTimeout: $2\$" "$CFG"
}

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
    && sed -i -E '/Channel: &ChannelCapabilities/,/Orderer: &OrdererCapabilities/ s/V3_0(_HYBRID)?: true/V3_0: true/' configtx/configtx.yaml
}

net_down() {
  cd "$TN" && ./network.sh down > "$1" 2>&1
  docker rm -f peer0org1_cityanchor_ccaas peer0org2_cityanchor_ccaas "$CAP" >/dev/null 2>&1   # network.sh's kill misses them
  true
}

der() { openssl x509 -in "$1" -outform DER 2>/dev/null | wc -c; }
height() { timeout 60 peer channel getinfo -c mychannel 2>/dev/null | grep -o '"height": *"\?[0-9]*' | grep -o '[0-9]*$'; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null; }

# ---------------------------------------------------------------- network up + chaincode + CLI invoke (common to every run)
bring_up() {   # $1 = cond, $2 = run directory, $3 = label ; leaves the shell in $TN with org1's peer CLI environment
  local cond=$1 D=$2 L=$3
  net_down "$D/down.log"
  configure "$cond" || return 1
  cd "$TN"
  if ! bgwait timeout 900 ./network.sh up createChannel -c mychannel -ca > "$D/up.log" 2>&1 || ! grep -q "Channel 'mychannel' joined" "$D/up.log"; then
    log "$L: network up FAILED (see $D/up.log)"; tail -5 "$D/up.log" >> "$LOG"; return 1; fi
  # the batch values written into the channel's genesis block (the paper's defaults: 512 KB, 2 s)
  local gb="" gt=""
  if FABRIC_CFG_PATH=$TN/configtx configtxgen -inspectBlock "$TN/channel-artifacts/mychannel.block" > "$D/genesis.json" 2> "$D/genesis.err" \
     && read -r gb gt < <(python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1]))["data"]["data"][0]["payload"]["data"]["config"]["channel_group"]["groups"]["Orderer"]["values"]
print(v["BatchSize"]["value"]["preferred_max_bytes"], v["BatchTimeout"]["value"]["timeout"])' "$D/genesis.json" 2>> "$D/genesis.err") \
     && [ -n "$gt" ]; then
    echo "preferred_max_bytes=$gb timeout=$gt" > "$D/batch_in_force.txt"
    if [ "$gb" != 524288 ] || [ "$gt" != 2s ]; then log "$L: genesis block holds preferred_max_bytes=$gb timeout=$gt, expected 524288 2s - run discarded"; return 1; fi
  else
    log "$L: WARNING could not inspect the genesis block (see $D/genesis.err); continuing"; echo "not verified" > "$D/batch_in_force.txt"
  fi
  if ! bgwait timeout 900 ./network.sh deployCCAAS -ccn cityanchor -ccp ~/pqc/cityanchor/chaincode > "$D/deploy.log" 2>&1 \
       || ! grep -q "Docker container started succesfully" "$D/deploy.log"; then
    log "$L: deployCCAAS FAILED (see $D/deploy.log)"; tail -5 "$D/deploy.log" >> "$LOG"; return 1; fi
  local O1=$TN/organizations/peerOrganizations/org1.example.com
  { echo "user1_msp_der $(der $O1/users/User1@org1.example.com/msp/signcerts/cert.pem)"
    echo "peer0org1_msp_der $(der $O1/peers/peer0.org1.example.com/msp/signcerts/cert.pem)"
    echo "orderer_msp_der $(der $TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/signcerts/orderer.example.com-cert.pem)"
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
    cp "$D/invoke.log" "$D/invoke_try$try.log"; log "$L: invoke attempt $try failed ($(grep -o "connect: [a-z ]*\|status:[0-9]*" "$D/invoke.log" | tail -1)), retrying in 10 s"
    sleep 10
  done
  if ! grep -q "status:200" "$D/invoke.log"; then
    log "$L: smoke invoke FAILED after 6 attempts"; tail -1 "$D/invoke.log" | tail -c 600 >> "$LOG"
    for c in peer0.org1.example.com orderer.example.com; do echo "-- $c" >> "$D/container_tail.log"; docker logs --tail 40 $c >> "$D/container_tail.log" 2>&1; done
    return 1; fi
  [ "$try" -gt 1 ] && log "$L: invoke succeeded on attempt $try"
  if [ -n "$hb" ]; then   # the invoke returns once the orderer accepts it; wait until its block is on the peer
    for w in $(seq 1 30); do [ "$(height)" -gt "$hb" ] 2>/dev/null && break; sleep 1; done
    [ "$(height)" -gt "$hb" ] 2>/dev/null || log "$L: WARNING height did not rise after the CLI invoke"
  fi
  sleep 3
  return 0
}

# ---------------------------------------------------------------- one benchmark (appends one CSV row; returns 0 if it ran)
# $1 exp $2 cond $3 rep $4 net $5 pos $6 chunk $7 n $8 conc $9 json path ${10} rtt fields "a,b,c"
bench() {
  local exp=$1 cond=$2 rep=$3 net=$4 pos=$5 chunk=$6 n=$7 conc=$8 J=$9 rtt=${10:-,,} h0 h1 to
  to=$(( n / 20 + 300 )); [ "$to" -lt 600 ] && to=600
  h0=$(height)
  ( cd "$BENCH" && FABRIC_SAMPLES=~/pqc/fabric-samples OUT_JSON="$J" COND=$cond REP=$rep \
      exec timeout $to node bench_night.mjs $n $conc ) > "${J%.json}.log" 2>&1 &
  CHILD=$!; wait "$CHILD"; CHILD=""
  sleep 3                      # let the last block commit on the peer before reading the height
  h1=$(height)
  if [ -s "$J" ]; then
    local fw; fw=$(node -p "require('$J').failed_workers" 2>/dev/null)
    [ "$fw" = 0 ] || log "$exp $cond rep$rep $net: WARNING $fw of $conc client workers stopped early (see ${J%.json}.log)"
    node -e "const f=(x,d)=>Number(x).toFixed(d);const r=require('$J');const l=r.latency_ms||{};console.log(['$exp','$cond','$rep','$net','$pos','$chunk',r.concurrency,r.n_tx,r.failed_workers,f(r.tx_per_s,2),f(l.mean,1),f(l.p50,1),f(l.p95,1),f(l.p99,1),f(r.wall_s,2),r.key_type,'$h0','$h1','$rtt'].join(','))" >> "$CSV"
    return 0
  fi
  log "$exp $cond rep$rep $net: bench FAILED"; tail -3 "${J%.json}.log" >> "$LOG"; return 1
}

# ---------------------------------------------------------------- netem on the node containers (phase C)
NODES="peer0.org1.example.com peer0.org2.example.com orderer.example.com"
NETEM_MODE=""      # prio (node-to-node only) | all (whole interface) | "" (unavailable)
shaper() {   # $1 = container, $2 = shell script ; runs in a helper container that shares the node's network namespace
  timeout 60 docker run --rm --net "container:$1" --cap-add NET_ADMIN "$NETSHOOT" sh -c "$2"
}
shape_on() {   # $1 = run directory ; every node delays and rate-limits its traffic to the other nodes
  local n o ips dev script f
  for n in $NODES; do
    ips=""; for o in $NODES; do [ "$o" = "$n" ] || ips="$ips $(ip_of "$o")"; done
    ips=${ips# }
    case "$ips" in *.*.*.*" "*.*.*.*) ;; *) echo "== $n: could not read the IPs of the other nodes ($ips)" >> "$1/netem.txt"; return 1 ;; esac
    dev='$(ip -o route get '"${ips%% *}"' | sed -E "s/.* dev ([^ ]+).*/\1/" | head -1)'
    if [ "$NETEM_MODE" = prio ]; then
      f=""; for o in $ips; do f="$f && tc filter add dev \$D parent 1: protocol ip prio 1 u32 match ip dst $o/32 flowid 1:4"; done
      script="D=$dev; tc qdisc del dev \$D root 2>/dev/null; tc qdisc add dev \$D root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 && tc qdisc add dev \$D parent 1:4 handle 40: netem delay $C_DELAY rate $C_RATE limit 10000 $f && tc qdisc show dev \$D && tc filter show dev \$D"
    else
      script="D=$dev; tc qdisc del dev \$D root 2>/dev/null; tc qdisc add dev \$D root netem delay $C_DELAY rate $C_RATE limit 10000 && tc qdisc show dev \$D"
    fi
    echo "== $n (targets:$ips)" >> "$1/netem.txt"
    shaper "$n" "$script" >> "$1/netem.txt" 2>&1 || { log "netem on $n FAILED (see $1/netem.txt)"; return 1; }
  done
  return 0
}
shape_off() {
  local n rc=0
  for n in $NODES; do
    shaper "$n" 'for D in $(ls /sys/class/net | grep -v "^lo$"); do tc qdisc del dev $D root 2>/dev/null; done; true' >> "$1/netem.txt" 2>&1 || rc=1
  done
  return $rc
}
rtt() {   # $1 = from container, $2 = to IP ; average round trip in ms ("" when ping fails)
  [ -n "$2" ] || return 0
  timeout 60 docker run --rm --net "container:$1" "$NETSHOOT" ping -c 5 -i 0.2 -q "$2" 2>/dev/null \
    | awk '/min\/avg/ { split($0, a, "= "); split(a[2], v, "/"); print v[2] }'
}

# ---------------------------------------------------------------- phase A: E5 + E1 + E2 on one network
run_A() {   # $1 = cond
  local cond=$1 D=$OUT/A/$1 t0=$(date +%s) L="A $1"
  mkdir -p "$D"
  bring_up "$cond" "$D" "$L" || return 1
  local TNO=$TN/organizations O1=$TN/organizations/peerOrganizations/org1.example.com O2=$TN/organizations/peerOrganizations/org2.example.com
  # E5 ledger: 2,000 alerts at 20 clients after the CLI invoke (the ledger of Table 12)
  if bench A "$cond" 1 none 1 "" "$A_N" "$A_CONC" "$D/bench_c$A_CONC.json"; then log "$L c$A_CONC: $(tail -1 "$CSV" | cut -d, -f8-11,14)"
  else return 1; fi
  docker exec peer0.org1.example.com sh -c 'cd /var/hyperledger/production/ledgersData && for p in * chains/* chains/chains/*; do du -sb "$p"; done 2>/dev/null' > "$D/ledger_du.txt" 2>&1
  docker exec peer0.org1.example.com ls -l /var/hyperledger/production/ledgersData/chains/chains/mychannel > "$D/blockfiles_ls.txt" 2>&1
  mkdir -p "$D/raw" "$D/certs"
  cp "$O1/users/User1@org1.example.com/msp/signcerts/cert.pem" "$D/certs/user1.pem"
  cp "$O1/peers/peer0.org1.example.com/msp/signcerts/cert.pem" "$D/certs/peer0org1.pem"
  cp "$O2/peers/peer0.org2.example.com/msp/signcerts/cert.pem" "$D/certs/peer0org2.pem"
  cp "$TNO/ordererOrganizations/example.com/orderers/orderer.example.com/msp/signcerts/orderer.example.com-cert.pem" "$D/certs/orderer.pem"
  local f files=()
  for f in $(docker exec peer0.org1.example.com ls /var/hyperledger/production/ledgersData/chains/chains/mychannel | grep '^blockfile_' | sort); do
    docker cp peer0.org1.example.com:/var/hyperledger/production/ledgersData/chains/chains/mychannel/$f "$D/raw/$f" > /dev/null 2>&1 && files+=("$D/raw/$f")
  done
  if [ ${#files[@]} -gt 0 ]; then
    python3 -I "$OUT/tools/decode_blockfile.py" "${files[0]}" --json "$D/decode_${files[0]##*/}.json" > /dev/null 2>&1 \
      || log "$L: decode of ${files[0]##*/} FAILED"
    if bgwait python3 -I "$OUT/tools/blockcomp.py" "${files[@]}" --certs "$D"/certs/*.pem --json "$D/blockcomp.json" > "$D/blockcomp.txt" 2>&1; then
      log "$L: E5 $(python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1])); p = d["per_block"]
print("raw/tx %s | per block: %s | whole file zstd3 -%s%% | trained dictionary -%s%% (zstd3 on the same blocks -%s%%)" % (
    d["raw_bytes_per_tx"], ", ".join("%s -%s%%" % (k, v["saving_pct"]) for k, v in p.items()), d["whole_file_zstd3"]["saving_pct"],
    d["trained_dictionary"].get("zstd3_trained_saving_pct"), d["trained_dictionary"].get("zstd3_saving_pct")))' "$D/blockcomp.json" 2>&1)"
    else log "$L: E5 blockcomp FAILED (see $D/blockcomp.txt)"; fi
  else log "$L: E5 no block files copied"; fi
  # E1 negative controls
  ( cd "$BENCH" && FABRIC_SAMPLES=~/pqc/fabric-samples COND=$cond OUT_JSON="$D/negctl.json" exec timeout 900 node negctl.mjs ) > "$D/negctl.log" 2>&1 &
  CHILD=$!; wait "$CHILD"; CHILD=""
  if [ -s "$D/negctl.json" ]; then
    log "$L: E1 $(node -e "const r=require('$D/negctl.json');console.log(r.passed+'/'+r.tests+' as expected | '+r.results.map(x=>x.test+':'+(x.stage==='commit'?x.code_name:x.stage)+(x.pass?'':'(UNEXPECTED)')).join(' '))")"
  else log "$L: E1 negctl FAILED (see $D/negctl.log)"; tail -5 "$D/negctl.log" >> "$LOG"; fi
  # E2 TLS groups of node-to-node connections
  if [ -n "$NETSHOOT_OK" ]; then run_E2 "$cond" "$D" "$L"; else log "$L: E2 skipped (no capture image)"; fi
  log "$L: done in $(( $(date +%s) - t0 )) s"
  return 0
}

run_E2() {   # $1 = cond, $2 = run directory, $3 = label
  local cond=$1 D=$2 L=$3 w ok=0
  docker network inspect fabric_test --format '{{range .Containers}}{{.IPv4Address}} {{.Name}}{{"\n"}}{{end}}' 2>/dev/null \
    | sed -E 's#/[0-9]+ # #' | grep -v '^$' > "$D/names.txt"
  echo "$(docker network inspect fabric_test --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null) host(docker-proxy)" >> "$D/names.txt"
  echo "127.0.0.1 host(loopback)" >> "$D/names.txt"
  docker rm -f "$CAP" > /dev/null 2>&1
  docker run --rm --name "$CAP" --net host --cap-add NET_ADMIN --cap-add NET_RAW "$NETSHOOT" \
    tcpdump -i any -U -s 4096 -w - tcp > "$D/tls.pcap" 2> "$D/tcpdump.log" &
  local CP=$!
  for w in $(seq 1 20); do docker ps --format '{{.Names}}' | grep -qx "$CAP" && grep -q "listening on" "$D/tcpdump.log" && break; sleep 1; done
  if ! docker ps --format '{{.Names}}' | grep -qx "$CAP"; then log "$L: E2 capture did not start (see $D/tcpdump.log)"; kill $CP 2>/dev/null; wait $CP 2>/dev/null; return 1; fi
  sleep 2
  # new node-to-node connections: restart both peers (deliver to the orderer, gossip, gateway to the other peer)
  bgwait timeout 180 docker restart peer0.org1.example.com peer0.org2.example.com > "$D/restart.log" 2>&1 || log "$L: E2 peer restart returned an error (see $D/restart.log)"
  for w in $(seq 1 60); do [ -n "$(height)" ] && break; sleep 2; done
  docker network inspect fabric_test --format '{{range .Containers}}{{.IPv4Address}} {{.Name}}{{"\n"}}{{end}}' 2>/dev/null \
    | sed -E 's#/[0-9]+ # #' | grep -v '^$' >> "$D/names.txt"; sort -u -o "$D/names.txt" "$D/names.txt"
  sleep 15
  if bench A_tls "$cond" 1 none 1 "" 40 4 "$D/bench_tls.json"; then ok=1
  else sleep 15; bench A_tls "$cond" 1 none 2 "" 40 4 "$D/bench_tls2.json" && ok=1; fi
  sleep 15                                 # gossip alive messages, deliver
  timeout 60 docker stop -t 5 "$CAP" > /dev/null 2>&1 || timeout 30 docker rm -f "$CAP" > /dev/null 2>&1
  ( sleep 30; kill $CP 2>/dev/null ) & local KP=$!
  wait $CP 2>/dev/null; kill $KP 2>/dev/null; wait $KP 2>/dev/null
  [ "$ok" = 1 ] || log "$L: E2 WARNING the short benchmark after the restart failed; node-to-node handshakes may be missing"
  if python3 -I "$OUT/tools/tlshello.py" "$D/tls.pcap" --names "$D/names.txt" --json "$D/tls_groups.json" > "$D/tls_groups.txt" 2>&1; then
    log "$L: E2 $(tr '\n' ';' < "$D/tls_groups.txt" | head -c 1500)"
  else log "$L: E2 tlshello FAILED (see $D/tls_groups.txt)"; fi
}

# ---------------------------------------------------------------- phase B: E4 long run
snapshot() {   # $1 = run directory, $2 = step, $3 = alerts so far
  local D=$1 s=$2 a=$3 h t p2 od
  h=$(height)
  # one du per path: a single du with overlapping arguments skips directories it has already counted
  t=$(docker exec peer0.org1.example.com sh -c 'cd /var/hyperledger/production/ledgersData && for p in * chains/* chains/chains/*; do du -sb "$p"; done 2>/dev/null' 2>/dev/null)
  echo "$t" | grep -q "chains/chains/mychannel" || log "$D: WARNING ledger sizes could not be read at step $s"
  echo "== step $s alerts $a height $h $(date +%s)" >> "$D/ledger_du_all.txt"; echo "$t" >> "$D/ledger_du_all.txt"
  docker exec peer0.org1.example.com ls -l /var/hyperledger/production/ledgersData/chains/chains/mychannel > "$D/blockfiles_ls_step$s.txt" 2>&1
  p2=$(docker exec peer0.org2.example.com du -sb /var/hyperledger/production/ledgersData 2>/dev/null | awk '{print $1}')
  od=$(docker exec orderer.example.com du -sb /var/hyperledger/production/orderer 2>/dev/null | awk '{print $1}')
  # columns: total, block files (chains/chains/mychannel), block index (chains/index), state, history, everything else
  echo "$t" | awk -v s="$s" -v a="$a" -v h="$h" -v p2="$p2" -v od="$od" -v ts="$(date +%s)" '
    { sz[$2] = $1 }
    END {
      tot = 0; for (k in sz) if (k !~ /\//) tot += sz[k]
      bf = sz["chains/chains/mychannel"] + 0; idx = sz["chains/index"] + 0
      st = sz["stateLeveldb"] + 0; hi = sz["historyLeveldb"] + 0
      printf "%s,%s,%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%s,%s,%s\n", s, a, h, tot, bf, idx, st, hi, tot - bf - idx - st - hi, p2, od, ts
    }' >> "$D/ledger_growth.csv"
}
run_B() {   # $1 = cond
  local cond=$1 D=$OUT/B/$1 t0=$(date +%s) L="B $1" k nchunks alerts=1 ok=0
  mkdir -p "$D"
  bring_up "$cond" "$D" "$L" || return 1
  echo "step,alerts,height,ledger_total,block_files,block_index,state_db,history_db,other,peer2_ledger_total,orderer_ledger_total,unix_time" > "$D/ledger_growth.csv"
  snapshot "$D" 0 "$alerts"
  nchunks=$(( B_ALERTS / B_CHUNK ))
  for k in $(seq 1 "$nchunks"); do
    stop_now && break
    if bench B "$cond" 1 none "$k" "$k" "$B_CHUNK" "$B_CONC" "$D/bench_chunk$k.json"; then
      alerts=$(( alerts + $(node -p "require('$D/bench_chunk$k.json').n_tx" 2>/dev/null || echo 0) )); ok=$((ok+1))
      sleep 5; snapshot "$D" "$k" "$alerts"
      log "$L chunk $k/$nchunks: $(tail -1 "$CSV" | cut -d, -f8-11) | alerts $alerts | ledger $(tail -1 "$D/ledger_growth.csv" | cut -d, -f4) B"
      progress "B $cond chunk $k/$nchunks done"
    else
      log "$L chunk $k: bench failed; stopping this condition"; break
    fi
  done
  log "$L: done in $(( $(date +%s) - t0 )) s ($ok/$nchunks chunks)"
  [ $ok -gt 0 ]
}

# ---------------------------------------------------------------- phase C: E3 constrained network
run_C() {   # $1 = cond, $2 = rep
  local cond=$1 rep=$2 D=$OUT/C/$1/rep$2 t0=$(date +%s) L="C $1 rep$2" net pos=0 ok=0 io ip2 icc ro rp rc
  mkdir -p "$D"
  bring_up "$cond" "$D" "$L" || return 1
  io=$(ip_of orderer.example.com); ip2=$(ip_of peer0.org2.example.com); icc=$(ip_of peer0org1_cityanchor_ccaas)
  for net in $(printf 'none\nwan\n' | shuf); do
    pos=$((pos+1))
    if [ "$net" = wan ]; then shape_on "$D" || { shape_off "$D"; log "$L: netem could not be applied; run discarded"; return 1; }
    else shape_off "$D" || log "$L: WARNING removing netem returned an error (see $D/netem.txt)"; fi
    ro=$(rtt peer0.org1.example.com "$io"); rp=$(rtt peer0.org1.example.com "$ip2"); rc=$(rtt peer0.org1.example.com "$icc")
    echo "$net pos$pos rtt peer0.org1->orderer=$ro peer0.org1->peer0.org2=$rp peer0.org1->chaincode=$rc" >> "$D/rtt.txt"
    # the CSV net label records what was verified: wan / wan_all (delay on all traffic) / none, or *_unverified
    local label=$net
    if [ "$net" = wan ]; then
      [ "$NETEM_MODE" = all ] && label=wan_all
      awk -v r="$ro" -v p="$rp" 'BEGIN{exit !(r>=15 && r<=40 && p>=15 && p<=40)}' || { log "$L: WARNING round trips with netem are orderer $ro ms, peer $rp ms (expected about 20)"; label=${label}_unverified; }
    else
      awk -v r="$ro" 'BEGIN{exit !(r!="" && r<5)}' || { log "$L: WARNING round trip without netem is $ro ms"; label=none_unverified; }
    fi
    if bench C "$cond" "$rep" "$label" "$pos" "" "$C_N" "$C_CONC" "$D/bench_${net}.json" "$ro,$rp,$rc"; then
      ok=$((ok+1)); log "$L $label: $(tail -1 "$CSV" | cut -d, -f8-11,14) | rtt orderer $ro ms, peer $rp ms, chaincode $rc ms"
    fi
    sleep 5
  done
  shape_off "$D"
  log "$L: done in $(( $(date +%s) - t0 )) s ($ok/2 benchmarks)"
  [ $ok -gt 0 ]
}

# ================================================================ preflight
log "revision run ($MODE) start; out=$OUT; hours=$HOURS"
log "plan: A conds='$A_CONDS' n=$A_N | B conds='$B_CONDS' alerts=$B_ALERTS chunk=$B_CHUNK | C conds='$C_CONDS' reps=$C_REPS n=$C_N delay=$C_DELAY rate=$C_RATE | DL=${DL:-none}"
PRE_FAIL=0; PRE_WARN=0
pre_ok()   { log "check OK    $*"; }
pre_warn() { log "check WARN  $*"; PRE_WARN=$((PRE_WARN+1)); }
pre_fail() { log "check FAIL  $*"; PRE_FAIL=$((PRE_FAIL+1)); }
for b in peer configtxgen fabric-ca-client node python3 openssl docker git shuf awk sha256sum zstd timeout; do
  command -v $b >/dev/null && pre_ok "$b on PATH" || pre_fail "$b not on PATH"; done
[ -f "$BENCH/node_modules/@hyperledger/fabric-gateway/package.json" ] && pre_ok "fabric-gateway $(node -p "require('$BENCH/node_modules/@hyperledger/fabric-gateway/package.json').version" 2>/dev/null) installed in $BENCH" || pre_fail "fabric-gateway not installed in $BENCH"
[ "$(sha256sum "$OUT/tools/bench_night.mjs" | cut -d' ' -f1)" = "$BENCH_SHA" ] && pre_ok "embedded benchmark client is the one of the paper's runs (sha256 ${BENCH_SHA:0:12})" || pre_fail "embedded benchmark client differs from the paper's (sha256)"
if [ -f "$BENCH/bench_night.mjs" ] && [ "$(sha256sum "$BENCH/bench_night.mjs" | cut -d' ' -f1)" != "$BENCH_SHA" ]; then
  pre_warn "$BENCH/bench_night.mjs differs from the paper's client; the run replaces it (a copy is kept as bench_night.mjs.before_revision)"; fi
if [ "$MODE" != check ]; then
  [ -f "$BENCH/bench_night.mjs" ] && ! cmp -s "$BENCH/bench_night.mjs" "$OUT/tools/bench_night.mjs" && cp "$BENCH/bench_night.mjs" "$BENCH/bench_night.mjs.before_revision"
  cp "$OUT/tools/bench_night.mjs" "$BENCH/bench_night.mjs" && cp "$OUT/tools/negctl.mjs" "$BENCH/negctl.mjs" || pre_fail "could not write the client files into $BENCH"
fi
node -e "require('crypto').generateKeyPairSync('ml-dsa-44')" 2>/dev/null && pre_ok "Node $(node -v) supports ML-DSA" || pre_fail "Node $(node -v) has no ML-DSA"
# the self-test imports fabric-gateway from $BENCH/node_modules, so it must run from a file inside $BENCH
cp "$OUT/tools/negctl.mjs" "$BENCH/.negctl_selftest.mjs" 2>/dev/null
st=$(cd "$BENCH" && NEGCTL_SELFTEST=1 timeout 300 node .negctl_selftest.mjs 2>&1 | tail -1); rm -f "$BENCH/.negctl_selftest.mjs"
[ "$st" = "SELFTEST OK" ] && pre_ok "negative-control tool self-test" || pre_fail "negative-control tool self-test: $st"
python3 -I -c 'import ast,sys; [ast.parse(open(f).read()) for f in sys.argv[1:]]' "$OUT"/tools/*.py && pre_ok "python tools parse" || pre_fail "python tools do not parse"
[ -d "$TN" ] && cd "$TN" && pre_ok "test network at $TN" || pre_fail "no test network at $TN"
if batch_line_counts_ok; then
  if grep -qE '^ *BatchTimeout: 2s$' "$CFG" && grep -qE '^ *PreferredMaxBytes: 512 KB$' "$CFG"; then pre_ok "orderer defaults in configtx.yaml (BatchTimeout 2s, PreferredMaxBytes 512 KB)"
  elif [ "$MODE" != check ] && grep -qE '^ *BatchTimeout: (2s|500ms)$' "$CFG" && grep -qE '^ *PreferredMaxBytes: (512 KB|1 MB)$' "$CFG"; then
    if set_batch "512 KB" "2s"; then MODIFIED=0; pre_warn "restored BatchTimeout 2s and PreferredMaxBytes 512 KB left by an interrupted block-cutting run"; else pre_fail "could not restore BatchTimeout 2s and PreferredMaxBytes 512 KB in $CFG"; fi
  else pre_fail "configtx.yaml does not hold BatchTimeout 2s and PreferredMaxBytes 512 KB"; grep -E '^ *(BatchTimeout|MaxMessageCount|PreferredMaxBytes):' "$CFG" >> "$LOG"; fi
else pre_fail "expected exactly one BatchTimeout and one PreferredMaxBytes line in $CFG"; fi
grep -qE '^ *MaxMessageCount: 10$' "$CFG" && pre_ok "MaxMessageCount 10" || pre_fail "MaxMessageCount is not 10 in $CFG"
if git -C "$TN" diff --quiet -- organizations/fabric-ca/ && grep -A12 "Channel: &ChannelCapabilities" "$CFG" | grep -q "^ *V3_0: true"; then pre_ok "CA files and channel capability at their defaults"
else pre_warn "CA files or channel capability not at their defaults (left by an interrupted run); every run restores them"; fi
others=$(docker ps -a --format '{{.Names}} {{.Label "com.docker.compose.project"}}' 2>/dev/null | awk '$1 ~ /^(peer0\.org[12]|orderer)\.example\.com$/ && $2 != "pqcnet" {print $1}' | xargs)
[ -z "$others" ] && pre_ok "no other Fabric network holds the container names" || pre_fail "containers of another compose project use the names: $others (stop that network first)"
free=$(df --output=avail -B1 ~ | tail -1)
[ "$free" -gt 15000000000 ] 2>/dev/null && pre_ok "free disk $(( free / 1000000000 )) GB" || pre_fail "less than 15 GB free in ~"
NETSHOOT_OK=""
if docker image inspect "$NETSHOOT" > /dev/null 2>&1 || timeout 600 docker pull -q "$NETSHOOT" > /dev/null 2>&1; then NETSHOOT_OK=1
elif timeout 600 docker pull -q nicolaka/netshoot:latest > /dev/null 2>&1; then NETSHOOT=nicolaka/netshoot:latest; NETSHOOT_OK=1; fi
if [ -n "$NETSHOOT_OK" ]; then
  pre_ok "helper image $NETSHOOT ($(docker image inspect -f '{{.Id}}' "$NETSHOOT" 2>/dev/null | cut -c8-19))"
  for t in tcpdump tc ping; do timeout 120 docker run --rm "$NETSHOOT" sh -c "command -v $t" > /dev/null 2>&1 || { pre_warn "$t missing in $NETSHOOT"; NETSHOOT_OK=""; }; done
else pre_warn "helper image $NETSHOOT could not be pulled: E2 (TLS capture) and E3 (netem) will be skipped"; fi
if [ -n "$NETSHOOT_OK" ]; then
  if timeout 120 docker run --rm --cap-add NET_ADMIN "$NETSHOOT" sh -c 'tc qdisc add dev eth0 root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 && tc qdisc add dev eth0 parent 1:4 handle 40: netem delay 10ms rate 100mbit limit 10000 && tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dst 192.0.2.1/32 flowid 1:4' > "$OUT/netem_check.txt" 2>&1; then
    NETEM_MODE=prio; pre_ok "netem with prio and u32 filters (node-to-node traffic only)"
  elif timeout 120 docker run --rm --cap-add NET_ADMIN "$NETSHOOT" sh -c 'tc qdisc add dev eth0 root netem delay 10ms rate 100mbit limit 10000' >> "$OUT/netem_check.txt" 2>&1; then
    NETEM_MODE=all; pre_warn "netem works but prio/u32 do not: the delay will apply to all traffic of the nodes, including chaincode (run 'sudo modprobe sch_prio cls_u32' once to fix)"
  else
    pre_warn "netem is not available in this kernel: E3 will be skipped (run 'sudo modprobe sch_netem sch_prio cls_u32' once, then start again)"; cat "$OUT/netem_check.txt" >> "$LOG"
  fi
fi
{ echo "== machine"; uname -a; nproc; free -g; df -h ~ | tail -1; lscpu | grep -m1 "Model name"
  echo "== software"; node -v; node -p '"openssl " + process.versions.openssl'; go version 2>/dev/null; zstd -V
  echo "fabric-gateway $(node -p "require('$BENCH/node_modules/@hyperledger/fabric-gateway/package.json').version" 2>/dev/null)"
  docker version --format 'docker {{.Server.Version}}'
  for r in fabric fabric-ca fabric-lib-go; do echo "$r $(git -C ~/pqc/$r rev-parse --short HEAD 2>/dev/null) $(git -C ~/pqc/$r rev-parse --abbrev-ref HEAD 2>/dev/null)"; done
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}' | grep -E "fabric-(peer|orderer|ca):pqc|ccaas|netshoot"
  peer version | head -4
  echo "== orderer batch settings"; grep -E '^ *(BatchTimeout|MaxMessageCount|AbsoluteMaxBytes|PreferredMaxBytes):' "$CFG"
  echo "== netem mode: ${NETEM_MODE:-unavailable}"
  echo "== bench client"; sha256sum "$BENCH/bench_night.mjs" "$BENCH/negctl.mjs"; } > "$OUT/environment.txt" 2>&1
git -C "$TN" diff --stat >> "$LOG" 2>&1
log "preflight: $PRE_FAIL failed, $PRE_WARN warnings"
if [ "$MODE" = check ] || [ "$PRE_FAIL" -gt 0 ]; then
  [ "$PRE_FAIL" -gt 0 ] && log "ABORT: fix the failed checks above, then start again"
  [ "$MODE" = check ] && [ "$PRE_FAIL" = 0 ] && log "check finished: ready for 'smoke' and 'full'"
  rm -rf "$OUT"/tools; exit $(( PRE_FAIL > 0 ))
fi
trap 'rc=$?; [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null; kill $(jobs -p) 2>/dev/null; docker rm -f "$CAP" >/dev/null 2>&1; if [ "$MODIFIED" = 1 ]; then restore_defaults && log "CA files and channel capability restored to the defaults" || log "WARNING: restore_defaults failed; check configtx.yaml and organizations/fabric-ca in $TN"; fi; log "script exit (code $rc)"' EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP

# ================================================================ plan and run
nA=$(printf '%s\n' $A_CONDS | grep -c .); nB=$(printf '%s\n' $B_CONDS | grep -c .); nC=$(printf '%s\n' $C_CONDS | grep -c .)
[ -n "$NETEM_MODE" ] || nC=0
PH_PLAN[A]=$nA; PH_PLAN[B]=$nB; PH_PLAN[C]=$(( nC * C_REPS ))
progress "start ($nA networks in phase A, $nB long runs, ${PH_PLAN[C]} constrained-network runs)"
STOPPED=0
for cond in $A_CONDS; do
  stop_now && { STOPPED=1; break; }
  progress "A $cond"; t_run=$(date +%s)
  run_A "$cond" || log "A $cond: run failed"
  finish_run A "$t_run" "A $cond"
done
for cond in $B_CONDS; do
  [ "$STOPPED" = 1 ] && break; stop_now && { STOPPED=1; break; }
  progress "B $cond"; t_run=$(date +%s)
  run_B "$cond" || log "B $cond: run failed"
  finish_run B "$t_run" "B $cond"
done
if [ "$nC" -gt 0 ]; then
  ACTIVE="$C_CONDS"; declare -A FAILS
  for rep in $(seq 1 "$C_REPS"); do
    [ "$STOPPED" = 1 ] && break
    mapfile -t ORDER < <(printf '%s\n' $ACTIVE | shuf)
    log "=== C repetition $rep order: ${ORDER[*]}"
    for cond in "${ORDER[@]}"; do
      stop_now && { STOPPED=1; break 2; }
      progress "C $cond rep $rep"; t_run=$(date +%s)
      if run_C "$cond" "$rep"; then FAILS[$cond]=0; else
        FAILS[$cond]=$(( ${FAILS[$cond]:-0} + 1 ))
        if [ "${FAILS[$cond]}" -ge 2 ]; then
          ACTIVE=$(printf '%s\n' $ACTIVE | grep -vx "$cond" | xargs); PH_PLAN[C]=$(( PH_PLAN[C] - (C_REPS - rep) ))
          log "dropping $cond from phase C after 2 failures in a row; active: $ACTIVE"
        fi
      fi
      finish_run C "$t_run" "C $cond rep $rep"
    done
    [ -z "$ACTIVE" ] && break
  done
else
  log "phase C skipped (netem unavailable)"
fi

# ================================================================ wrap up
net_down "$OUT/final_down.log"; restore_defaults && MODIFIED=0 && log "CA files and channel capability restored to the defaults"
log "summary rows: $(( $(wc -l < "$CSV") - 1 ))"
python3 -I "$OUT/tools/summarize_revision.py" "$OUT" > "$OUT/summary_tables.txt" 2>&1 && log "wrote summary_tables.txt" || log "summarize_revision.py FAILED (see summary_tables.txt)"
NAME=$(basename "$OUT")
tar czf ~/pqc/results/$NAME.tgz -C ~/pqc/results --exclude='blockfile_00000*' --exclude='*.pcap' "$NAME" && log "packed: ~/pqc/results/$NAME.tgz ($(stat -c %s ~/pqc/results/$NAME.tgz) B)"
PACK=~/pqc/results/$NAME.tgz
if [ -n "$DL" ] && [ -d "$DL" ]; then
  cp ~/pqc/results/$NAME.tgz "$DL/" && cp "$OUT/summary_tables.txt" "$DL/${NAME}_summary_tables.txt" && PACK=$DL/$NAME.tgz && log "copied to $DL"
fi
log "ALL DONE - results: $PACK"
touch "$OUT/DONE"
{ echo "finished $(date '+%F %T') - total time $(hm $(( $(date +%s) - START )))"; echo "results: $PACK"; } > "$STATUS"
cat "$STATUS"
