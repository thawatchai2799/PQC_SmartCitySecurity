#!/usr/bin/env python3
"""Summary tables from one results directory written by scripts/night_run.sh.

Usage: python3 tools/summarize.py results/night_YYYYMMDD_HHMM [--json out.json]

Prints, per condition and concurrency, the mean and 95% confidence interval (t distribution) of
throughput and latency; the block-file composition per transaction; the ledger size after 4,001
alerts with its projection to one year at 10 alerts per second; and container CPU per transaction
at 50 clients. Benchmarks in which a client worker failed are excluded and listed.
"""
import csv
import glob
import json
import math
import os
import re
import statistics as st
import sys

CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]
T95 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262,
       11: 2.228, 12: 2.201, 13: 2.179, 14: 2.160, 15: 2.145}
YEAR_S = 365.25 * 24 * 3600
GROUPS = {
    "certificates": ["payload_header", "action_header", "endorser_cert"],
    "signatures": ["envelope_signature", "endorser_signature"],
    "block_metadata": ["block_metadata"],
    "application": ["proposal_payload", "proposal_hash", "rwset", "response_events_ccid"],
}


def mci(v):
    m = st.mean(v)
    if len(v) < 2:
        return m, float("nan"), len(v)
    return m, T95.get(len(v), 1.96) * st.stdev(v) / math.sqrt(len(v)), len(v)


def main(d, out_json=None):
    rows = list(csv.DictReader(open(os.path.join(d, "summary.csv"))))
    bad = [r for r in rows if int(r["n_tx"]) <= 0 or r["failed_workers"] != "0"]
    ok = [r for r in rows if r not in bad]
    res = {"excluded": bad, "perf": {}, "bytes": {}, "ledger": {}, "cpu_c50": {}}
    print(f"benchmarks: {len(rows)}, excluded: {len(bad)}")
    for r in bad:
        print("  excluded:", r["cond"], "rep", r["rep"], "c", r["concurrency"], "n_tx", r["n_tx"])

    concs = sorted({int(r["concurrency"]) for r in rows})
    print("\nthroughput (tx/s) and mean latency (ms): mean +- 95% CI, change vs ECDSA")
    for c in concs:
        base = None
        for cond in CONDS:
            s = [r for r in ok if r["cond"] == cond and int(r["concurrency"]) == c]
            if not s:
                continue
            o = {m: mci([float(r[m]) for r in s]) for m in ("tx_per_s", "mean_ms", "p50_ms", "p99_ms")}
            res["perf"][f"{cond}_c{c}"] = o
            if cond == "ecdsa":
                base = o["tx_per_s"][0]
            ch = f"{(o['tx_per_s'][0] / base - 1) * 100:+.0f}%" if base else ""
            print(f"  c{c:<4} {cond:9s} n={o['tx_per_s'][2]:2d}  {o['tx_per_s'][0]:7.1f} +- {o['tx_per_s'][1]:5.1f} {ch:>5}"
                  f"   latency {o['mean_ms'][0]:7.1f} +- {o['mean_ms'][1]:5.1f}  p99 {o['p99_ms'][0]:7.1f}")

    print("\nblock-file bytes per transaction (decoded block files of the first successful run)")
    for cond in CONDS:
        files = []
        for rep in sorted(glob.glob(os.path.join(d, cond, "rep*")), key=lambda p: int(re.sub(r"\D", "", os.path.basename(p)))):
            files = sorted(glob.glob(os.path.join(rep, "decode_blockfile_00000*.json")))
            if files:
                break
        if not files:
            continue
        tot, tx, fb, bl = {}, 0, 0, 0
        for f in files:
            j = json.load(open(f))
            for k, v in j["bytes"].items():
                tot[k] = tot.get(k, 0) + v
            tx += j["transactions"]; fb += j["file_bytes"]; bl += j["blocks"]
        g = {k: sum(tot.get(x, 0) for x in v) / tx for k, v in GROUPS.items()}
        res["bytes"][cond] = {"per_tx": fb / tx, "tx": tx, "blocks": bl, "tx_per_block": tx / bl,
                              "metadata_per_block": tot["block_metadata"] / bl, **g,
                              "categories": {k: v / tx for k, v in tot.items()}}
        print(f"  {cond:9s} {fb / tx:9.1f} B/tx  certificates {g['certificates'] / (fb / tx) * 100:4.1f}%  "
              f"signatures {g['signatures'] / (fb / tx) * 100:4.1f}%  tx/block {tx / bl:5.2f}  "
              f"metadata/block {tot['block_metadata'] / bl:7.0f}")

    print("\nledger after 4,001 alerts (mean of runs) and projection at 10 alerts/s")
    print("  (a run is left out when its c20 or c50 benchmark was excluded, since it then holds fewer alerts)")
    short = {(r["cond"], str(int(r["rep"]))) for r in bad if int(r["concurrency"]) in (20, 50)}
    base = None
    for cond in CONDS:
        v = []
        for f in glob.glob(os.path.join(d, cond, "rep*", "du_after_c20_c50.txt")):
            rep = re.sub(r"\D", "", os.path.basename(os.path.dirname(f)))
            if (cond, str(int(rep))) in short:
                print(f"  left out: {cond} rep{rep}")
                continue
            v.append(int(open(f).read().split()[0]))
        if not v:
            continue
        m = st.mean(v)
        base = base or m
        tb = m / 4001 * 10 * YEAR_S / 1e12
        res["ledger"][cond] = {"mean_bytes": m, "sd_bytes": st.stdev(v) if len(v) > 1 else 0, "n": len(v),
                               "ratio": m / base, "tb_per_year_10aps": tb}
        print(f"  {cond:9s} {m / 1e6:8.2f} MB  x{m / base:5.2f}  {tb:6.2f} TB/year  (n={len(v)})")

    print("\nCPU at 50 clients: mean % and ms per committed transaction")
    for cond in CONDS:
        acc = {}
        for f in glob.glob(os.path.join(d, cond, "rep*", "stats_c50.csv")):
            for line in open(f):
                p = line.strip().split(",")
                if len(p) < 3:
                    continue
                try:
                    acc.setdefault(p[1], []).append(float(p[2].rstrip("%")))
                except ValueError:
                    pass
        tps = res["perf"].get(f"{cond}_c50", {}).get("tx_per_s", (float("nan"),))[0]
        out = {n: (st.mean(v), st.mean(v) / 100 * 1000 / tps) for n, v in acc.items()
               if re.search("peer0|orderer|ccaas", n)}
        res["cpu_c50"][cond] = out
        print(f"  {cond:9s} " + "  ".join(f"{n}: {a:5.1f}% {b:5.2f} ms/tx" for n, (a, b) in sorted(out.items())))

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
