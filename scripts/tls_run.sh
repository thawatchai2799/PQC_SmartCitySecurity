#!/usr/bin/env bash
# tls_run.sh - which TLS key exchange the Fabric nodes and the client actually negotiate, per condition.
#
# For each condition the network is brought up with the condition's MSP identities (no chaincode is
# needed), and every TLS endpoint a client or node connects to is probed:
#   peer0.org1 (7051), peer0.org2 (9051), orderer (7050) and the org1 CA (7054)
# from two client stacks:
#   tools/tlsprobe (Go, built here with the local Go toolchain: the TLS stack of peers and orderer)
#   tools/tls_probe_node.mjs (Node.js and its OpenSSL: the stack of the benchmark client and fabric-gateway)
# each with three key-exchange settings (default, X25519 only, X25519MLKEM768 only), N full handshakes
# per setting. The build information (Go version, DefaultGODEBUG) of the peer, orderer and CA binaries
# inside the images is recorded, as are the TLS certificate sizes.
#
# Start (inside WSL):  bash ~/pqc/tls_run.sh            (about 10 to 15 minutes; DL=<folder> also copies the results)
# Tunables: CONDS="ecdsa mldsa44 mldsa65 mldsa87 hybrid44"  N=50
# It never touches other Fabric networks: everything runs under compose project "pqcnet" in ~/pqc.
# no 'set -u': fabric-samples' envVar.sh reads unset variables (e.g. OVERRIDE_ORG)
CONDS=${CONDS:-"ecdsa mldsa44 mldsa65 mldsa87 hybrid44"}; N=${N:-50}
TN=~/pqc/fabric-samples/test-network; CFG=$TN/configtx/configtx.yaml
DL=${DL:-}
OUT=~/pqc/results/tls_$(date +%Y%m%d_%H%M%S); mkdir -p "$OUT/tools/tlsprobe"
LOG=$OUT/progress.log
export COMPOSE_PROJECT_NAME=pqcnet PATH=~/pqc/bin:$PATH
START=$(date +%s)
MODIFIED=0

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
CHILD=""
bgwait() { "$@" & CHILD=$!; wait "$CHILD"; local rc=$?; CHILD=""; return $rc; }

# ---------------------------------------------------------------- embedded helper files
cat > "$OUT/tools/tlsprobe/main.go" <<'TLSPROBE_GO_EOF'
// tlsprobe - TLS handshakes against one endpoint with three key-exchange settings.
//
// Usage: tlsprobe -addr localhost:7051 -sni peer0.org1.example.com -ca ca.crt [-n 50] [-name peer0.org1]
//
// For each setting the probe performs n full handshakes (no session resumption) and prints one JSON
// line with the negotiated TLS version, cipher suite and key-exchange group, the bytes written and
// read on the wire during the first handshake, and the median and 90th-percentile handshake time.
// Settings: "default" (the Go defaults of the probe's toolchain, which offer X25519MLKEM768 first),
// "x25519" (classical only) and "mlkem" (X25519MLKEM768 only). The server certificate chain is
// recorded and then verified separately against -ca; the handshake itself does not verify it, so
// that a verification failure does not hide the key exchange.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"sort"
	"time"
)

type counting struct {
	net.Conn
	r, w int64
}

func (c *counting) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.r += int64(n)
	return n, err
}
func (c *counting) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.w += int64(n)
	return n, err
}

type result struct {
	Client       string  `json:"client"`
	Name         string  `json:"endpoint"`
	Addr         string  `json:"addr"`
	Mode         string  `json:"mode"`
	OK           bool    `json:"ok"`
	Err          string  `json:"error,omitempty"`
	Version      string  `json:"version,omitempty"`
	Cipher       string  `json:"cipher,omitempty"`
	Group        string  `json:"group,omitempty"`
	ALPN         string  `json:"alpn,omitempty"`
	BytesWritten int64   `json:"bytes_written"`
	BytesRead    int64   `json:"bytes_read"`
	N            int     `json:"n"`
	MedianMs     float64 `json:"handshake_ms_median"`
	P90Ms        float64 `json:"handshake_ms_p90"`
	CertSigAlg   string  `json:"server_cert_signature_algorithm,omitempty"`
	CertKeyAlg   string  `json:"server_cert_public_key_algorithm,omitempty"`
	ChainDER     int     `json:"server_chain_der_bytes"`
	ChainLen     int     `json:"server_chain_length"`
	Verified     bool    `json:"chain_verified"`
	VerifyErr    string  `json:"verify_error,omitempty"`
	GoVersion    string  `json:"probe_go_version"`
}

// algNames returns the signature and public-key algorithm of a certificate, falling back to the
// object identifiers when crypto/x509 does not know the algorithm (for example ML-DSA).
func algNames(c *x509.Certificate) (sig, key string) {
	sig, key = c.SignatureAlgorithm.String(), c.PublicKeyAlgorithm.String()
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		if _, err := asn1.Unmarshal(c.Raw, &outer); err == nil {
			sig = "OID " + outer.Alg.Algorithm.String()
		}
	}
	if c.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		var spki struct {
			Alg pkix.AlgorithmIdentifier
			Key asn1.BitString
		}
		if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
			key = "OID " + spki.Alg.Algorithm.String()
		}
	}
	return sig, key
}

// groupOf reads ConnectionState.CurveID (Go 1.25 and later) without requiring it at compile time.
func groupOf(st tls.ConnectionState) string {
	f := reflect.ValueOf(st).FieldByName("CurveID")
	if !f.IsValid() {
		return "unknown (probe built with Go < 1.25)"
	}
	if id, ok := f.Interface().(tls.CurveID); ok {
		if id == 0 {
			return "none"
		}
		return id.String()
	}
	return fmt.Sprint(f.Interface())
}

func main() {
	addr := flag.String("addr", "", "host:port")
	sni := flag.String("sni", "", "server name")
	caFile := flag.String("ca", "", "PEM file of the TLS root(s) for the separate verification")
	name := flag.String("name", "", "label for the output")
	n := flag.Int("n", 50, "handshakes per setting")
	flag.Parse()
	roots := x509.NewCertPool()
	if pem, err := os.ReadFile(*caFile); err == nil {
		roots.AppendCertsFromPEM(pem)
	}
	modes := []struct {
		name   string
		curves []tls.CurveID
	}{{"default", nil}, {"x25519", []tls.CurveID{tls.X25519}}, {"mlkem", []tls.CurveID{tls.X25519MLKEM768}}}
	enc := json.NewEncoder(os.Stdout)
	for _, m := range modes {
		r := result{Client: "go", Name: *name, Addr: *addr, Mode: m.name, GoVersion: runtime.Version()}
		var times []float64
		for i := 0; i < *n; i++ {
			raw, err := net.DialTimeout("tcp", *addr, 10*time.Second)
			if err != nil {
				r.Err = err.Error()
				break
			}
			c := &counting{Conn: raw}
			cfg := &tls.Config{ServerName: *sni, InsecureSkipVerify: true, CurvePreferences: m.curves,
				NextProtos: []string{"h2"}, SessionTicketsDisabled: true, MinVersion: tls.VersionTLS12}
			tc := tls.Client(c, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t0 := time.Now()
			err = tc.HandshakeContext(ctx)
			dt := time.Since(t0)
			cancel()
			if err != nil {
				r.Err = err.Error()
				raw.Close()
				break
			}
			times = append(times, float64(dt.Microseconds())/1000)
			if i == 0 {
				st := tc.ConnectionState()
				r.Version = tls.VersionName(st.Version)
				r.Cipher = tls.CipherSuiteName(st.CipherSuite)
				r.Group = groupOf(st)
				r.ALPN = st.NegotiatedProtocol
				r.BytesWritten, r.BytesRead = c.w, c.r
				r.ChainLen = len(st.PeerCertificates)
				for _, pc := range st.PeerCertificates {
					r.ChainDER += len(pc.Raw)
				}
				if len(st.PeerCertificates) > 0 {
					leaf := st.PeerCertificates[0]
					r.CertSigAlg, r.CertKeyAlg = algNames(leaf)
					inter := x509.NewCertPool()
					for _, pc := range st.PeerCertificates[1:] {
						inter.AddCert(pc)
					}
					_, verr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: *sni})
					r.Verified = verr == nil
					if verr != nil {
						r.VerifyErr = verr.Error()
					}
				}
			}
			tc.Close()
		}
		r.N = len(times)
		r.OK = r.Err == "" && r.N == *n
		if len(times) > 0 {
			sort.Float64s(times)
			r.MedianMs = times[len(times)/2]
			r.P90Ms = times[(len(times)*9)/10]
			if r.P90Ms == 0 {
				r.P90Ms = times[len(times)-1]
			}
		}
		enc.Encode(r)
	}
}
TLSPROBE_GO_EOF
cat > "$OUT/tools/tlsprobe/go.mod" <<'TLSPROBE_MOD_EOF'
module tlsprobe

go 1.24
TLSPROBE_MOD_EOF
cat > "$OUT/tools/tls_probe_node.mjs" <<'TLS_PROBE_NODE_EOF'
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
TLS_PROBE_NODE_EOF
cat > "$OUT/tools/summarize_tls.py" <<'SUMMARIZE_TLS_EOF'
#!/usr/bin/env python3
"""Summary of a results directory written by scripts/tls_run.sh.

Usage: python3 tools/summarize_tls.py results/tls_YYYYMMDD_HHMM

For every condition, endpoint and client (Go, the stack of the Fabric nodes; Node.js, the stack of the
benchmark client and fabric-gateway) the table gives the key-exchange group negotiated with the
client's default settings, the bytes read and written during that handshake and with X25519 forced,
the median handshake time of both, and the server certificate. The group is the one reported by Go
(ConnectionState.CurveID) or, where the client does not report it (Node.js for hybrid groups, Go
before 1.25), inferred from the bytes read: an X25519MLKEM768 server share carries a 1088-byte ML-KEM
ciphertext more than an X25519 one.
"""
import glob
import json
import os
import sys

CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]


def group(rows):
    d, x, m = rows.get("default"), rows.get("x25519"), rows.get("mlkem")
    if not d or not d.get("ok"):
        return "failed: " + (d or {}).get("error", "no result")[:60]
    g = d.get("group") or ""
    if g and not g.startswith("unknown") and g != "none":
        return g
    key = d.get("ephemeral_key") or {}
    if x and x.get("ok") and d["bytes_read"] - x["bytes_read"] > 800:
        return "X25519MLKEM768 (inferred from bytes)"
    if key.get("name"):
        return key["name"]
    if x and x.get("ok") and abs(d["bytes_read"] - x["bytes_read"]) < 100:
        return "X25519 (inferred from bytes)"
    return "undetermined"


def main(d):
    print(f"TLS key exchange per condition, endpoint and client ({d})")
    print(f"{'condition':9s} {'endpoint':12s} {'client':6s} {'default group':38s} {'read B':>7s} {'(x25519)':>8s} "
          f"{'written B':>9s} {'(x25519)':>8s} {'ms':>6s} {'(x25519)':>8s} {'mlkem-only':>10s}  server certificate")
    for cond in CONDS:
        p = os.path.join(d, cond, "probe.jsonl")
        if not os.path.exists(p):
            continue
        res = {}
        for line in open(p):
            line = line.strip()
            if not line.startswith("{"):
                continue
            r = json.loads(line)
            res.setdefault((r["endpoint"], r["client"]), {})[r["mode"]] = r
        for (ep, cl), rows in sorted(res.items()):
            dft, x, m = rows.get("default", {}), rows.get("x25519", {}), rows.get("mlkem", {})
            cert = dft.get("server_cert_signature_algorithm") or ""
            if dft.get("server_chain_der_bytes"):
                cert += f" chain {dft['server_chain_der_bytes']} B"
            if "chain_verified" in dft:
                cert += " verified" if dft["chain_verified"] else " not verified"
            merr = (m.get("error") or "failed").lower()
            mk = ("ok" if m.get("ok") else "-" if not dft.get("ok") else
                  "refused" if ("handshake failure" in merr or "alert number 40" in merr) else merr[:10])
            f = lambda r, k, fmt="{:.0f}": fmt.format(r[k]) if r.get("ok") and r.get(k) is not None else "-"
            print(f"{cond:9s} {ep:12s} {cl:6s} {group(rows):38s} {f(dft, 'bytes_read'):>7s} {f(x, 'bytes_read'):>8s} "
                  f"{f(dft, 'bytes_written'):>9s} {f(x, 'bytes_written'):>8s} {f(dft, 'handshake_ms_median', '{:.2f}'):>6s} "
                  f"{f(x, 'handshake_ms_median', '{:.2f}'):>8s} {mk:>10s}  {cert}")
    bi = os.path.join(d, "binaries_buildinfo.txt")
    if os.path.exists(bi):
        print("\nbuild information of the Fabric binaries (go version -m):")
        print(open(bi).read().rstrip())


if __name__ == "__main__":
    main(sys.argv[1])
SUMMARIZE_TLS_EOF
cp "$0" "$OUT/tools/tls_run.sh" 2>/dev/null

# ---------------------------------------------------------------- preflight
log "tls run start; out=$OUT; conds='$CONDS' n=$N"
for b in peer configtxgen fabric-ca-client node python3 openssl docker git; do command -v $b >/dev/null || { log "ABORT: $b not on PATH"; exit 1; }; done
[ -z "$DL" ] || [ -d "$DL" ] || { log "ABORT: DL=$DL is not a directory"; exit 1; }
for cond in $CONDS; do
  case $cond in ecdsa|mldsa44|mldsa65|mldsa87|hybrid44) ;; *) log "ABORT: unknown condition $cond"; exit 1 ;; esac
done
cd "$TN" || exit 1
grep -qE '^ *BatchTimeout: 2s$' "$CFG" && grep -qE '^ *PreferredMaxBytes: 512 KB$' "$CFG" \
  || { log "ABORT: $CFG does not hold the default batch settings; run blockcut_run.sh once with REPS=0 RAW_CONDS= to restore them"; exit 1; }
GOPROBE=""
if command -v go >/dev/null; then
  # the go line of go.mod sets the default GODEBUG: use the local toolchain's version, so that the probe
  # has the same TLS defaults as binaries built with it
  if ( cd "$OUT/tools/tlsprobe" && GOTOOLCHAIN=local go mod edit -go="$(go env GOVERSION | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')" \
       && GOTOOLCHAIN=local GOFLAGS=-mod=mod go build -o tlsprobe . && go version -m tlsprobe ) > "$OUT/tools/tlsprobe/build.log" 2>&1; then
    GOPROBE=$OUT/tools/tlsprobe/tlsprobe
    log "built the Go probe with $(go version | awk '{print $3}'); $(grep -o 'DefaultGODEBUG=[^ ]*' "$OUT/tools/tlsprobe/build.log" || echo 'no DefaultGODEBUG overrides')"
  else
    log "WARNING: the Go probe did not build (see tools/tlsprobe/build.log); only the Node.js probe will run"
  fi
else
  log "WARNING: go not on PATH; only the Node.js probe will run"
fi
trap 'rc=$?; [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null; [ "$MODIFIED" = 1 ] && restore_defaults && log "CA files and channel capability restored to the defaults"; log "script exit (code $rc)"' EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP
{ echo "== machine"; uname -a; lscpu | grep -m1 "Model name"
  echo "== software"; node -v; node -p '"openssl " + process.versions.openssl'; go version 2>/dev/null; openssl version
  docker version --format 'docker {{.Server.Version}}'
  for r in fabric fabric-ca fabric-lib-go; do echo "$r $(git -C ~/pqc/$r rev-parse --short HEAD 2>/dev/null) $(git -C ~/pqc/$r rev-parse --abbrev-ref HEAD 2>/dev/null)"; done
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}' | grep -E "fabric-(peer|orderer|ca):pqc"
} > "$OUT/environment.txt" 2>&1

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
  docker rm -f peer0org1_cityanchor_ccaas peer0org2_cityanchor_ccaas >/dev/null 2>&1   # network.sh's kill misses them
  true
}

der() { openssl x509 -in "$1" -outform DER 2>/dev/null | wc -c; }

# ---------------------------------------------------------------- build information of the binaries in the images (once)
buildinfo() {   # needs a running network
  local tmp=$OUT/tools/bin_tmp f c
  mkdir -p "$tmp"
  for c in "peer0.org1.example.com:/usr/local/bin/peer" "orderer.example.com:/usr/local/bin/orderer" "ca_org1:/usr/local/bin/fabric-ca-server"; do
    f=$tmp/$(basename "${c#*:}")
    if docker cp "$c" "$f" > /dev/null 2>&1; then
      echo "== ${c%%:*} ${c#*:}"
      if command -v go >/dev/null; then
        go version -m "$f" 2>&1 | grep -E "^$f: |^[[:space:]]+(path|mod)[[:space:]]|^[[:space:]]+build[[:space:]]+(DefaultGODEBUG|GOEXPERIMENT|GOFIPS140|-tags|vcs.revision)" | sed "s#$tmp/##"
      fi
    else
      echo "== ${c%%:*} ${c#*:}: could not copy"
    fi
  done
  rm -rf "$tmp"
}

# ---------------------------------------------------------------- one condition
run_cond() {   # $1 = cond
  local cond=$1 D=$OUT/$1 t0=$(date +%s) ep name addr sni ca
  mkdir -p "$D"
  net_down "$D/down.log"
  configure "$cond" || return 1
  cd "$TN"
  if ! bgwait timeout 900 ./network.sh up createChannel -c mychannel -ca > "$D/up.log" 2>&1 || ! grep -q "Channel 'mychannel' joined" "$D/up.log"; then
    log "$cond: network up FAILED (see $D/up.log)"; tail -5 "$D/up.log" >> "$LOG"; return 1; fi
  sleep 5
  local O1=$TN/organizations/peerOrganizations/org1.example.com O2=$TN/organizations/peerOrganizations/org2.example.com
  local OO=$TN/organizations/ordererOrganizations/example.com
  { echo "peer0org1_tls_der $(der $O1/peers/peer0.org1.example.com/tls/server.crt)"
    echo "peer0org1_tls_ca_der $(der $O1/peers/peer0.org1.example.com/tls/ca.crt)"
    echo "orderer_tls_der $(der $OO/orderers/orderer.example.com/tls/server.crt)"
    echo "ca_org1_tls_der $(der $TN/organizations/fabric-ca/org1/tls-cert.pem)"
    echo "== peer0.org1 TLS server certificate"
    openssl x509 -in $O1/peers/peer0.org1.example.com/tls/server.crt -noout -text 2>&1 | grep -m3 -E "Signature Algorithm|Public Key Algorithm|Public-Key"
    echo "== peer0.org1 TLS CA certificate"
    openssl x509 -in $O1/peers/peer0.org1.example.com/tls/ca.crt -noout -text 2>&1 | grep -m3 -E "Signature Algorithm|Public Key Algorithm|Public-Key"
    echo "== org1 CA server TLS certificate (port 7054)"
    openssl x509 -in $TN/organizations/fabric-ca/org1/tls-cert.pem -noout -text 2>&1 | grep -m3 -E "Signature Algorithm|Public Key Algorithm|Public-Key"
  } > "$D/tls_certs.txt" 2>&1
  [ -f "$OUT/binaries_buildinfo.txt" ] || buildinfo > "$OUT/binaries_buildinfo.txt" 2>&1
  : > "$D/probe.jsonl"
  for ep in "peer0.org1|localhost:7051|peer0.org1.example.com|$O1/peers/peer0.org1.example.com/tls/ca.crt" \
            "peer0.org2|localhost:9051|peer0.org2.example.com|$O2/peers/peer0.org2.example.com/tls/ca.crt" \
            "orderer|localhost:7050|orderer.example.com|$OO/tlsca/tlsca.example.com-cert.pem" \
            "ca_org1|localhost:7054|localhost|$TN/organizations/fabric-ca/org1/ca-cert.pem"; do
    IFS='|' read -r name addr sni ca <<< "$ep"
    if [ -n "$GOPROBE" ]; then
      bgwait timeout 300 "$GOPROBE" -addr "$addr" -sni "$sni" -ca "$ca" -n "$N" -name "$name" >> "$D/probe.jsonl" 2>> "$D/probe.err"
    fi
    bgwait timeout 300 node "$OUT/tools/tls_probe_node.mjs" "$addr" "$sni" "$ca" "$name" "$N" >> "$D/probe.jsonl" 2>> "$D/probe.err"
    log "$cond $name: $(grep "\"endpoint\":\"$name\"" "$D/probe.jsonl" | grep '"mode":"default"' | python3 -I -c '
import sys, json
for l in sys.stdin:
    r = json.loads(l); g = r.get("group") or r.get("ephemeral_key") or ""
    print(r["client"], "ok" if r.get("ok") else "FAILED " + r.get("error", "")[:80], r.get("version", ""), g, "read", r.get("bytes_read", "-"), end="; ")')"
  done
  log "$cond: done in $(( $(date +%s) - t0 )) s"
  return 0
}

# ---------------------------------------------------------------- main
for cond in $CONDS; do
  run_cond "$cond" || log "$cond: FAILED"
done
net_down "$OUT/final_down.log"; restore_defaults && MODIFIED=0 && log "CA files and channel capability restored to the defaults"
python3 -I "$OUT/tools/summarize_tls.py" "$OUT" > "$OUT/summary_tables.txt" 2>&1 && log "wrote summary_tables.txt" || log "summarize_tls.py FAILED (see summary_tables.txt)"
NAME=$(basename "$OUT")
tar czf ~/pqc/results/$NAME.tgz -C ~/pqc/results --exclude="$NAME/tools/tlsprobe/tlsprobe" "$NAME" && log "packed: ~/pqc/results/$NAME.tgz ($(stat -c %s ~/pqc/results/$NAME.tgz) B)"
PACK=~/pqc/results/$NAME.tgz
if [ -n "$DL" ]; then cp ~/pqc/results/$NAME.tgz "$DL/" && PACK=$DL/$NAME.tgz && log "copied to $DL"; fi
log "ALL DONE in $(( ($(date +%s) - START) / 60 )) min - results: $PACK"
cat "$OUT/summary_tables.txt"
