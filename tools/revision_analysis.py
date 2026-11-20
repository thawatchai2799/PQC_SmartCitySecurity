"""Derived numbers from the revision run (E1..E5) for the manuscript and the response letter.

Usage: python3 rev_analysis.py <revision_full_... directory> <out.json>
"""
import csv
import glob
import json
import math
import os
import sys
from collections import defaultdict

import numpy as np
from scipy import stats

R = sys.argv[1]
OUT = sys.argv[2]
NAME = {"ecdsa": "ECDSA", "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87", "hybrid44": "Hybrid-44"}
CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]
res = {}


def ci(xs):
    xs = np.asarray(xs, float)
    n = len(xs)
    h = stats.t.ppf(0.975, n - 1) * xs.std(ddof=1) / math.sqrt(n) if n > 1 else float("nan")
    return float(xs.mean()), float(h), n


rows = list(csv.DictReader(open(os.path.join(R, "summary.csv"))))
for r in rows:
    for k in ("tx_per_s", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "wall_s"):
        r[k] = float(r[k])
    for k in ("rtt_orderer_ms", "rtt_peer_ms", "rtt_chaincode_ms"):
        r[k] = float(r[k]) if r[k] else None
assert all(r["failed_workers"] == "0" for r in rows), "a benchmark had a stopped worker"

# ---------------------------------------------------------------- E1
print("== E1 negative controls")
e1 = {}
for c in CONDS:
    d = json.load(open(os.path.join(R, "A", c, "negctl.json")))
    e1[c] = {"tests": d["tests"], "passed": d["passed"], "client_key": d["client_key"], "endorser_keys": d["endorser_keys_org1"],
             "results": {x["test"]: {"stage": x["stage"], "code": x["code_name"], "pass": x["pass"], "checks": x["checks"],
                                      "error": (x["error"] or "")[:200], "block": x.get("block")} for x in d["results"]}}
    print(f"{NAME[c]:10} {d['passed']}/{d['tests']} client key {d['client_key']}, endorser keys {d['endorser_keys_org1']}")
    for x in d["results"]:
        if not x["pass"]:
            print("   UNEXPECTED", x["test"], x["stage"], x["code_name"], x["error"])
res["E1"] = e1
tot = sum(v["tests"] for v in e1.values())
print(f"total {sum(v['passed'] for v in e1.values())}/{tot} as expected; T0 re-encoding byte-identical: "
      + str({c: e1[c]['results']['T0']['checks'].get('reencoding_byte_identical') for c in CONDS}))

# ---------------------------------------------------------------- E2
print("\n== E2 TLS groups (connections opened after the peer restart)")
e2 = {}
for c in CONDS:
    d = json.load(open(os.path.join(R, "A", c, "tls_groups.json")))
    n2n = {k: v for k, v in d["by_endpoint_pair"].items() if "example.com" in k.split(" -> ")[0] and "example.com" in k.split(" -> ")[1]}
    groups = set(g for v in d["by_endpoint_pair"].values() for g in v)
    n2n_conns = sum(sum(v.values()) for v in n2n.values())
    # client hello details of node-to-node connections: offered key shares and version
    offered = set()
    for cn in d["connections"]:
        if "example.com" in cn["client"] and "example.com" in cn["server"]:
            offered.add((tuple(cn["client_hello"]["key_share_groups"]), cn["server_hello"]["version"], cn["server_hello"].get("key_share_bytes")))
    e2[c] = {"tls_connections": d["tls_connections"], "node_to_node_pairs": n2n, "node_to_node_connections": n2n_conns,
             "all_groups_seen": sorted(groups), "node_to_node_offered_and_version": sorted(map(list, offered))}
    print(f"{NAME[c]:10} {d['tls_connections']} TLS connections, {n2n_conns} node-to-node over {len(n2n)} pairs; groups seen {sorted(groups)}; offered/version {sorted(offered)}")
res["E2"] = e2

# ---------------------------------------------------------------- E3
print("\n== E3 constrained network (20 clients, paired by network)")
e3 = {}
crows = [r for r in rows if r["exp"] == "C"]
for c in ("ecdsa", "mldsa44", "mldsa87"):
    by = defaultdict(dict)
    for r in crows:
        if r["cond"] == c:
            by[r["rep"]][r["net"]] = r
    pairs = [v for v in by.values() if "none" in v and "wan" in v]
    assert len(pairs) == 10, (c, len(pairs))
    none_t = [v["none"]["tx_per_s"] for v in pairs]
    wan_t = [v["wan"]["tx_per_s"] for v in pairs]
    lr = np.log([w / n for n, w in zip(none_t, wan_t)])
    gm = math.exp(lr.mean())
    h = stats.t.ppf(0.975, 9) * lr.std(ddof=1) / math.sqrt(10)
    lat_none = [v["none"]["mean_ms"] for v in pairs]
    lat_wan = [v["wan"]["mean_ms"] for v in pairs]
    p99_none = [v["none"]["p99_ms"] for v in pairs]
    p99_wan = [v["wan"]["p99_ms"] for v in pairs]
    llr = np.log([w / n for n, w in zip(lat_none, lat_wan)])
    lh = stats.t.ppf(0.975, 9) * llr.std(ddof=1) / math.sqrt(10)
    e3[c] = {
        "none_tx": ci(none_t), "wan_tx": ci(wan_t), "none_mean_ms": ci(lat_none), "wan_mean_ms": ci(lat_wan),
        "none_p99_ms": ci(p99_none), "wan_p99_ms": ci(p99_wan),
        "throughput_ratio_gm": gm, "throughput_ratio_logt95": [math.exp(lr.mean() - h), math.exp(lr.mean() + h)],
        "latency_ratio_gm": math.exp(llr.mean()), "latency_ratio_logt95": [math.exp(llr.mean() - lh), math.exp(llr.mean() + lh)],
        "paired_t_p": float(stats.ttest_rel(wan_t, none_t).pvalue), "wilcoxon_p": float(stats.wilcoxon(wan_t, none_t).pvalue),
        "wan_slower_in": int(sum(w < n for n, w in zip(none_t, wan_t))),
        "wan_first": int(sum(v["wan"]["pos"] == "1" for v in pairs)),
        "rtt_none_orderer": ci([v["none"]["rtt_orderer_ms"] for v in pairs]), "rtt_wan_orderer": ci([v["wan"]["rtt_orderer_ms"] for v in pairs]),
        "rtt_wan_peer": ci([v["wan"]["rtt_peer_ms"] for v in pairs]), "rtt_wan_chaincode": ci([v["wan"]["rtt_chaincode_ms"] for v in pairs]),
        "none_runs": none_t, "wan_runs": wan_t,
    }
    print(f"{NAME[c]:10} none {e3[c]['none_tx'][0]:6.1f} ± {e3[c]['none_tx'][1]:4.1f}  wan {e3[c]['wan_tx'][0]:6.1f} ± {e3[c]['wan_tx'][1]:4.1f}  "
          f"ratio {gm:.3f} [{e3[c]['throughput_ratio_logt95'][0]:.3f}, {e3[c]['throughput_ratio_logt95'][1]:.3f}]  "
          f"latency x{e3[c]['latency_ratio_gm']:.2f} [{e3[c]['latency_ratio_logt95'][0]:.2f}, {e3[c]['latency_ratio_logt95'][1]:.2f}]  "
          f"paired t p={e3[c]['paired_t_p']:.1e} wan slower {e3[c]['wan_slower_in']}/10, wan first {e3[c]['wan_first']}/10; "
          f"rtt wan orderer {e3[c]['rtt_wan_orderer'][0]:.2f} peer {e3[c]['rtt_wan_peer'][0]:.2f} chaincode {e3[c]['rtt_wan_chaincode'][0]:.2f} ms")
# ratios across conditions under wan vs none
for net in ("none", "wan"):
    e = np.mean(e3["ecdsa"][f"{net}_runs"])
    print(f"   {net}: ML-DSA-44 / ECDSA = {np.mean(e3['mldsa44'][net + '_runs']) / e:.3f}, ML-DSA-87 / ECDSA = {np.mean(e3['mldsa87'][net + '_runs']) / e:.3f}")
# the gap between constrained and loopback, difference between conditions (paired across the 10 networks is not possible across conditions; use Welch on per-network log ratios)
for a, b in (("mldsa44", "ecdsa"), ("mldsa87", "ecdsa"), ("mldsa87", "mldsa44")):
    la = np.log(np.array(e3[a]["wan_runs"]) / np.array(e3[a]["none_runs"]))
    lb = np.log(np.array(e3[b]["wan_runs"]) / np.array(e3[b]["none_runs"]))
    p = stats.ttest_ind(la, lb, equal_var=False).pvalue
    print(f"   netem penalty {NAME[a]} vs {NAME[b]}: Welch on per-network log ratios p = {p:.3f}")
    e3[f"penalty_{a}_vs_{b}_welch_p"] = float(p)
res["E3"] = e3

# ---------------------------------------------------------------- E4
print("\n== E4 long runs")
e4 = {}
for c in ("ecdsa", "mldsa44"):
    g = list(csv.DictReader(open(os.path.join(R, "B", c, "ledger_growth.csv"))))
    for r in g:
        for k in r:
            r[k] = int(r[k]) if r[k] not in ("",) else None
    pts = [r for r in g if r["step"] > 0]
    x = np.array([r["alerts"] for r in pts], float)
    fit = {}
    for key in ("ledger_total", "block_files", "block_index", "state_db", "history_db", "peer2_ledger_total", "orderer_ledger_total"):
        y = np.array([r[key] for r in pts], float)
        sl, ic, rv, _, se = stats.linregress(x, y)
        fit[key] = {"bytes_per_alert": float(sl), "intercept": float(ic), "r2": float(rv ** 2), "slope_se": float(se)}
    last = g[-1]
    share = {k: last[k] / last["ledger_total"] for k in ("block_files", "block_index", "state_db", "history_db", "other")}
    brows = sorted([r for r in rows if r["exp"] == "B" and r["cond"] == c], key=lambda r: int(r["chunk"]))
    tps = [r["tx_per_s"] for r in brows]
    hist = [r["history_db"] for r in g]
    e4[c] = {"alerts_final": last["alerts"], "height_final": last["height"], "ledger_total_final": last["ledger_total"],
             "fit": fit, "share_final": share, "tps_per_chunk": tps, "tps_first_last": [tps[0], tps[-1]],
             "tps_trend_p": float(stats.linregress(range(len(tps)), tps).pvalue), "history_db_by_step": hist,
             "orderer_minus_peer_final": last["orderer_ledger_total"] - last["ledger_total"],
             "orderer_step0": g[0]["orderer_ledger_total"], "per_alert_overall": last["ledger_total"] / last["alerts"]}
    print(f"{NAME[c]:10} {last['alerts']} alerts, height {last['height']}, ledger {last['ledger_total']/1e6:.1f} MB; "
          f"fit ledger {fit['ledger_total']['bytes_per_alert']:.0f} B/alert (R2 {fit['ledger_total']['r2']:.6f}), block files {fit['block_files']['bytes_per_alert']:.0f} (R2 {fit['block_files']['r2']:.7f}), "
          f"index {fit['block_index']['bytes_per_alert']:.0f}, state {fit['state_db']['bytes_per_alert']:.0f}, history {fit['history_db']['bytes_per_alert']:.0f}; "
          f"shares final: blocks {share['block_files']:.3f} index {share['block_index']:.3f} state {share['state_db']:.3f} history {share['history_db']:.3f}; "
          f"tps first {tps[0]:.1f} last {tps[-1]:.1f} min {min(tps):.1f} max {max(tps):.1f} (trend p {e4[c]['tps_trend_p']:.3f}); orderer-peer {e4[c]['orderer_minus_peer_final']/1e6:.1f} MB, orderer at step 0 {g[0]['orderer_ledger_total']/1e6:.1f} MB; history by step {hist}")
# compare with the main-run figures (Table 10 bytes per alert after 4001 alerts; incremental 4001->8001)
print("   main-run B/alert (Table 10): ECDSA 6061, ML-DSA-44 33512; incremental 6025 / 33289; E4 fit: "
      f"{e4['ecdsa']['fit']['ledger_total']['bytes_per_alert']:.0f} / {e4['mldsa44']['fit']['ledger_total']['bytes_per_alert']:.0f}")
res["E4"] = e4

# ---------------------------------------------------------------- E5
print("\n== E5 per-block compression")
e5 = {}
for c in CONDS:
    d = json.load(open(os.path.join(R, "A", c, "blockcomp.json")))
    p = d["per_block"]
    e5[c] = {"transactions": d["transactions"], "blocks": d["transaction_blocks"], "raw_bytes_per_tx": d["raw_bytes_per_tx"],
             "gzip6": p["gzip6"], "zstd3": p["zstd3"], "zstd3_certs": p["zstd3_certs"], "whole_file_zstd3": d["whole_file_zstd3"],
             "trained": d["trained_dictionary"], "cert_dictionary_bytes": d["cert_dictionary_bytes"],
             "certificates": d["certificates"], "zstd_version": d["zstd_version"]}
    print(f"{NAME[c]:10} tx {d['transactions']} blocks {d['transaction_blocks']} raw {d['raw_bytes_per_tx']:.0f} B/tx | gzip6 -{p['gzip6']['saving_pct']}% zstd3 -{p['zstd3']['saving_pct']}% "
          f"zstd3+certs -{p['zstd3_certs']['saving_pct']}% ({p['zstd3_certs']['bytes_per_tx']:.0f} B/tx) | whole file -{d['whole_file_zstd3']['saving_pct']}% | "
          f"trained: plain -{d['trained_dictionary']['zstd3_saving_pct']}% dict -{d['trained_dictionary']['zstd3_trained_saving_pct']}% (dict {d['trained_dictionary']['dictionary_bytes']} B) | cert dict {d['cert_dictionary_bytes']} B")
res["E5"] = e5
# relation to the identity-reference estimate of Table 12 (reference saving 72.9-73.8%)
print("   Table 12 reference saving 72.9-73.8% of the stored file; per-block zstd+certs: " + ", ".join(f"{NAME[c]} {e5[c]['zstd3_certs']['saving_pct']}%" for c in CONDS[1:]))

# ---------------------------------------------------------------- phase A benchmark vs Table 6 (third session)
print("\n== Phase A benchmark at 20 clients (third session) vs Table 6 means")
t5 = {"ecdsa": 170.0, "mldsa44": 134.3, "mldsa65": 101.1, "mldsa87": 78.5, "hybrid44": 126.9}
pa = {}
for r in rows:
    if r["exp"] == "A":
        pa[r["cond"]] = r["tx_per_s"]
        print(f"{NAME[r['cond']]:10} {r['tx_per_s']:6.1f} vs Table 6 {t5[r['cond']]:6.1f} ({100*(r['tx_per_s']/t5[r['cond']]-1):+.0f}%)  p99 {r['p99_ms']:.0f} ms")
res["phaseA"] = pa
res["E3_none_vs_table5"] = {c: [e3[c]["none_tx"][0], t5[c]] for c in ("ecdsa", "mldsa44", "mldsa87")}
print("E3 'none' means vs Table 6: " + ", ".join(f"{NAME[c]} {e3[c]['none_tx'][0]:.1f} vs {t5[c]}" for c in ("ecdsa", "mldsa44", "mldsa87")))

json.dump(res, open(OUT, "w"), indent=1, default=str)
print("wrote", OUT)
