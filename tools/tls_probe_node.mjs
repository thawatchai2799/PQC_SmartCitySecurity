// tls_probe_node.mjs - TLS handshakes from Node.js (the client stack of the benchmark and of
// @hyperledger/fabric-gateway, which uses Node's TLS through grpc-js) against one endpoint.
//
// Usage: node tls_probe_node.mjs <host:port> <sni> <ca.pem> <name> [n=50]
//
// Three settings: "default" (Node's default groups, which with OpenSSL 3.5 put X25519MLKEM768
// first), "x25519" and "mlkem" (ecdhCurve forced). For each, n full handshakes over a fresh TCP
// socket; one JSON line with the protocol, cipher, Node's ephemeral-key report, the encrypted bytes
// written and read on the TCP socket up to the end of the handshake, and the handshake time.
// The chain is not required to verify (rejectUnauthorized false); whether it did is reported.
import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';

const [addr, sni, caFile, name, nArg] = process.argv.slice(2);
const [host, port] = [addr.slice(0, addr.lastIndexOf(':')), Number(addr.slice(addr.lastIndexOf(':') + 1))];
const n = Number(nArg || 50);
let ca;
try { ca = readFileSync(caFile); } catch { ca = undefined; }

function once(secureContext) {
  return new Promise((resolve) => {
    const raw = net.connect(port, host);
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    const timer = setTimeout(() => { raw.destroy(); finish({ error: 'timeout' }); }, 10000);
    raw.on('error', (e) => { clearTimeout(timer); finish({ error: e.message }); });
    raw.on('connect', () => {
      const t0 = process.hrtime.bigint();
      const opts = { socket: raw, servername: sni, secureContext, rejectUnauthorized: false, ALPNProtocols: ['h2'], session: undefined };
      let s;
      try { s = tls.connect(opts); } catch (e) { clearTimeout(timer); raw.destroy(); finish({ error: e.message }); return; }
      s.on('error', (e) => { clearTimeout(timer); raw.destroy(); finish({ error: e.message }); });
      s.on('secureConnect', () => {
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        const r = { ms, protocol: s.getProtocol(), cipher: s.getCipher()?.name, key: s.getEphemeralKeyInfo(),
                    alpn: s.alpnProtocol || '', authorized: s.authorized, authError: s.authorizationError ? String(s.authorizationError) : '',
                    written: raw.bytesWritten, read: raw.bytesRead };
        clearTimeout(timer); s.destroy(); finish(r);
      });
    });
  });
}

for (const [mode, curve] of [['default', null], ['x25519', 'X25519'], ['mlkem', 'X25519MLKEM768']]) {
  const out = { client: 'node', endpoint: name, addr, mode, ok: false, n: 0, node: process.version, openssl: process.versions.openssl };
  const times = [];
  let ctx;   // built once per setting, before any handshake is timed
  try { ctx = tls.createSecureContext(curve ? { ca, ecdhCurve: curve } : { ca }); }
  catch (e) { out.error = e.message; console.log(JSON.stringify(out)); continue; }
  for (let i = 0; i < n; i++) {
    const r = await once(ctx);
    if (r.error) { out.error = r.error; break; }
    times.push(r.ms);
    if (i === 0) Object.assign(out, { version: r.protocol, cipher: r.cipher, ephemeral_key: r.key, alpn: r.alpn,
      bytes_written: r.written, bytes_read: r.read, chain_verified: r.authorized, verify_error: r.authError });
  }
  out.n = times.length; out.ok = !out.error && out.n === n;
  if (times.length) { times.sort((a, b) => a - b); out.handshake_ms_median = times[Math.floor(times.length / 2)]; out.handshake_ms_p90 = times[Math.floor(times.length * 9 / 10)] ?? times[times.length - 1]; }
  console.log(JSON.stringify(out));
}
