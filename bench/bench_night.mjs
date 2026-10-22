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
