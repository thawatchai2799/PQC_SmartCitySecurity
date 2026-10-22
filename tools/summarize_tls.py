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
