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
