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
