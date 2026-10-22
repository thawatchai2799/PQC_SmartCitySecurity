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
