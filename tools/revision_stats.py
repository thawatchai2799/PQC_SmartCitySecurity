"""Statistics for the major revision (reviewer 2, statistics comment).

Input: night_20261022_0144/summary.csv (main runs) and blockcut_20261022_1109/summary.csv.
The benchmark with a stopped worker (failed_workers != 0) is excluded, as in the paper.

Outputs (stdout and JSON):
  1. per-repetition ratios to ECDSA (throughput and mean latency) at each concurrency, with
     95% bootstrap percentile CIs over repetitions (10,000 resamples, seed 1) and a mixed-model
     style alternative: paired t CI on log ratios;
  2. Friedman test across conditions within repetitions, per concurrency; Shapiro-Wilk per cell;
  3. paired Hybrid-44 vs ML-DSA-44 (paired t and Wilcoxon) per concurrency;
  4. losses relative to ECDSA at all four concurrencies, mean-of-ratios and ratio-of-means;
  5. Holm correction for the twelve Welch tests of Section 5.6 (block cutting);
  6. the session drift: ML-DSA-44 default-setting block-cutting runs vs main runs at 20 clients;
  7. standard deviations for Tables 5 and 9.
"""
import csv
import json
import math
import sys
from collections import defaultdict

import numpy as np
from scipy import stats

NIGHT = sys.argv[1]
BLOCKCUT = sys.argv[2]
OUT = sys.argv[3] if len(sys.argv) > 3 else "revision_stats.json"
CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]
NAMES = {"ecdsa": "ECDSA", "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87", "hybrid44": "Hybrid-44"}
CONC = [10, 20, 50, 100]
rng = np.random.default_rng(1)
R = {}


def load(path):
    rows = list(csv.DictReader(open(path)))
    for r in rows:
        for k in ("concurrency", "n_tx", "failed_workers", "rep"):
            r[k] = int(r[k])
        for k in ("tx_per_s", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "wall_s"):
            r[k] = float(r[k])
    return rows


night = [r for r in load(NIGHT)]
excluded = [r for r in night if r["failed_workers"] != 0]
night = [r for r in night if r["failed_workers"] == 0]
print(f"main runs: {len(night)} benchmarks kept, {len(excluded)} excluded: "
      + ", ".join(f"{r['cond']} rep{r['rep']} c{r['concurrency']}" for r in excluded))

cell = defaultdict(dict)   # (cond, conc) -> {rep: row}
for r in night:
    cell[(r["cond"], r["concurrency"])][r["rep"]] = r


def ci_t(xs):
    xs = np.asarray(xs, float)
    n = len(xs)
    if n < 2:
        return float(xs.mean()), float("nan"), float("nan")
    h = stats.t.ppf(0.975, n - 1) * xs.std(ddof=1) / math.sqrt(n)
    return float(xs.mean()), float(xs.mean() - h), float(xs.mean() + h)


def boot_mean(xs, n_boot=10000):
    xs = np.asarray(xs, float)
    idx = rng.integers(0, len(xs), size=(n_boot, len(xs)))
    means = xs[idx].mean(axis=1)
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


# ---------------------------------------------------------------- 1 + 4. paired ratios to ECDSA
print("\n== 1. Ratios to ECDSA within each repetition (throughput; mean latency), bootstrap 95% CI over repetitions")
R["ratios"] = {}
hdr = f"{'cond':10} {'conc':>4} {'n':>2} {'mean ratio':>10} {'boot 95% CI':>18} {'paired t CI (log)':>20} {'ratio of means':>14} {'loss %':>7} | {'latency ratio':>13} {'boot CI':>16}"
print(hdr)
for c in CONDS[1:]:
    for k in CONC:
        reps = sorted(set(cell[("ecdsa", k)]) & set(cell[(c, k)]))
        tr = np.array([cell[(c, k)][p]["tx_per_s"] / cell[("ecdsa", k)][p]["tx_per_s"] for p in reps])
        lr = np.array([cell[(c, k)][p]["mean_ms"] / cell[("ecdsa", k)][p]["mean_ms"] for p in reps])
        lo, hi = boot_mean(tr)
        llo, lhi = boot_mean(lr)
        m, tlo, thi = ci_t(np.log(tr))
        rom = np.mean([cell[(c, k)][p]["tx_per_s"] for p in reps]) / np.mean([cell[("ecdsa", k)][p]["tx_per_s"] for p in reps])
        R["ratios"][f"{c}_c{k}"] = {"n_pairs": len(reps), "throughput_ratio_mean": float(tr.mean()), "throughput_ratio_boot95": [lo, hi],
                                   "throughput_ratio_logt95": [math.exp(tlo), math.exp(thi)], "ratio_of_means": float(rom),
                                   "loss_pct_mean_of_ratios": float(100 * (1 - tr.mean())), "loss_pct_ratio_of_means": float(100 * (1 - rom)),
                                   "latency_ratio_mean": float(lr.mean()), "latency_ratio_boot95": [llo, lhi]}
        print(f"{NAMES[c]:10} {k:>4} {len(reps):>2} {tr.mean():>10.3f} [{lo:.3f}, {hi:.3f}]     [{math.exp(tlo):.3f}, {math.exp(thi):.3f}]      {rom:>14.3f} {100*(1-tr.mean()):>7.1f} | {lr.mean():>13.2f} [{llo:.2f}, {lhi:.2f}]")

# ---------------------------------------------------------------- 2. Friedman and Shapiro-Wilk
print("\n== 2. Friedman test across the five conditions within repetitions (throughput), and Shapiro-Wilk per cell")
R["friedman"] = {}
R["shapiro"] = {}
for k in CONC:
    reps = sorted(set.intersection(*[set(cell[(c, k)]) for c in CONDS]))
    data = [[cell[(c, k)][p]["tx_per_s"] for p in reps] for c in CONDS]
    st, p = stats.friedmanchisquare(*data)
    R["friedman"][f"c{k}"] = {"n_reps": len(reps), "chi2": float(st), "p": float(p)}
    print(f"c{k:<3} complete repetitions {len(reps)}: Friedman chi2 = {st:.2f}, p = {p:.2e}")
sw_rej = 0
for c in CONDS:
    for k in CONC:
        xs = [r["tx_per_s"] for r in cell[(c, k)].values()]
        w, p = stats.shapiro(xs)
        R["shapiro"][f"{c}_c{k}"] = {"n": len(xs), "W": float(w), "p": float(p)}
        sw_rej += p < 0.05
print(f"Shapiro-Wilk rejects normality (p < 0.05) in {sw_rej} of {len(CONDS)*len(CONC)} throughput cells: "
      + ", ".join(f"{NAMES[c]}@{k}" for c in CONDS for k in CONC if R["shapiro"][f"{c}_c{k}"]["p"] < 0.05))

# repetition effect: mean over conditions per repetition, relative to the grand mean
print("\n   repetition effect (mean throughput over the five conditions, per repetition, relative to the mean over repetitions)")
R["rep_effect"] = {}
for k in CONC:
    reps = sorted(set.intersection(*[set(cell[(c, k)]) for c in CONDS]))
    per_rep = {p: np.mean([cell[(c, k)][p]["tx_per_s"] for c in CONDS]) for p in reps}
    g = np.mean(list(per_rep.values()))
    R["rep_effect"][f"c{k}"] = {str(p): float(100 * (v / g - 1)) for p, v in per_rep.items()}
    print(f"   c{k:<3} " + " ".join(f"r{p}:{100*(v/g-1):+5.1f}%" for p, v in per_rep.items()))

# ---------------------------------------------------------------- 3. Hybrid-44 vs ML-DSA-44 paired
print("\n== 3. Hybrid-44 vs ML-DSA-44, paired by repetition (throughput)")
R["hybrid_paired"] = {}
for k in CONC:
    reps = sorted(set(cell[("hybrid44", k)]) & set(cell[("mldsa44", k)]))
    h = np.array([cell[("hybrid44", k)][p]["tx_per_s"] for p in reps])
    m = np.array([cell[("mldsa44", k)][p]["tx_per_s"] for p in reps])
    d = h / m - 1
    t, pt = stats.ttest_rel(h, m)
    try:
        w, pw = stats.wilcoxon(h, m)
    except ValueError:
        w, pw = float("nan"), float("nan")
    lo, hi = boot_mean(d)
    slower = int((h < m).sum())
    R["hybrid_paired"][f"c{k}"] = {"n": len(reps), "mean_diff_pct": float(100 * d.mean()), "boot95_pct": [100 * lo, 100 * hi],
                                   "paired_t_p": float(pt), "wilcoxon_p": float(pw), "hybrid_slower_in": slower,
                                   "welch_p": float(stats.ttest_ind(h, m, equal_var=False).pvalue)}
    print(f"c{k:<3} n={len(reps)} hybrid/ML-DSA-44 - 1 = {100*d.mean():+.1f}% [{100*lo:+.1f}, {100*hi:+.1f}]  paired t p = {pt:.3f}  Wilcoxon p = {pw:.3f}  Welch p = {R['hybrid_paired'][f'c{k}']['welch_p']:.3f}  slower in {slower}/{len(reps)}")

# ---------------------------------------------------------------- 7. SD for Table 6
print("\n== 7. Table 6 with standard deviations (throughput tx/s): mean ± 95% CI (SD) [min, max]")
R["table5_sd"] = {}
for c in CONDS:
    row = []
    for k in CONC:
        xs = np.array([r["tx_per_s"] for r in cell[(c, k)].values()])
        m, lo, hi = ci_t(xs)
        R["table5_sd"][f"{c}_c{k}"] = {"n": len(xs), "mean": m, "ci_half": m - lo, "sd": float(xs.std(ddof=1)), "min": float(xs.min()), "max": float(xs.max())}
        row.append(f"{m:6.1f} ± {m-lo:4.1f} ({xs.std(ddof=1):4.1f}) [{xs.min():.0f}, {xs.max():.0f}]")
    print(f"{NAMES[c]:10} " + " | ".join(row))

# ---------------------------------------------------------------- 5. Holm on the block-cutting Welch tests
print("\n== 5. Block cutting (Section 5.6): Welch tests with Holm correction")
bc = [r for r in load(BLOCKCUT) if r["phase"] == "main" and r["failed_workers"] == 0]   # the paper uses the main phase only
phases = sorted({r["phase"] for r in load(BLOCKCUT)})
print(f"   phases in file: {phases}; rows used: {len(bc)}")
settings = sorted({r["setting"] for r in bc})
print(f"   settings: {settings}")
base = "pmb512k_bt2s"
tests = []
for c in ("mldsa44", "mldsa87"):
    for s in [x for x in settings if x != base]:
        for k in (10, 20, 50):
            for metric in ("tx_per_s", "p99_ms"):
                a = [r[metric] for r in bc if r["cond"] == c and r["setting"] == base and r["concurrency"] == k]
                b = [r[metric] for r in bc if r["cond"] == c and r["setting"] == s and r["concurrency"] == k]
                if len(a) >= 2 and len(b) >= 2:
                    p = stats.ttest_ind(a, b, equal_var=False).pvalue
                    tests.append({"cond": c, "setting": s, "conc": k, "metric": metric, "n": [len(a), len(b)],
                                  "mean_base": float(np.mean(a)), "mean_alt": float(np.mean(b)),
                                  "change_pct": float(100 * (np.mean(b) / np.mean(a) - 1)), "p": float(p)})
# Holm over the twelve ML-DSA-87 tests (the ones the paper reports), and over all tests
def holm(ts):
    m = len(ts)
    order = sorted(range(m), key=lambda i: ts[i]["p"])
    adj_prev = 0.0
    for rank, i in enumerate(order):
        adj = min(1.0, (m - rank) * ts[i]["p"])
        adj = max(adj, adj_prev)
        ts[i]["p_holm"] = adj
        adj_prev = adj
t87 = [t for t in tests if t["cond"] == "mldsa87"]
t44 = [t for t in tests if t["cond"] == "mldsa44"]
holm(t87)
holm(t44)
R["blockcut_holm"] = {"mldsa87": t87, "mldsa44": t44}
for c, ts in (("mldsa87", t87), ("mldsa44", t44)):
    print(f"   {NAMES[c]}: {len(ts)} tests, Holm family size {len(ts)}")
    for t in sorted(ts, key=lambda t: (t["setting"], t["conc"], t["metric"])):
        flag = "*" if t["p_holm"] < 0.05 else " "
        print(f"     {t['setting']:14} c{t['conc']:<3} {t['metric']:8} {t['mean_base']:8.1f} -> {t['mean_alt']:8.1f} ({t['change_pct']:+6.1f}%)  p = {t['p']:.4f}  Holm p = {t['p_holm']:.4f} {flag}")

# ---------------------------------------------------------------- 6. session drift
print("\n== 6. Session drift: ML-DSA-44 default setting, block-cutting session vs main session, 20 clients")
R["drift"] = {}
for c in ("mldsa44", "mldsa87", "ecdsa"):
    for k in (10, 20, 50):
        a = [r["tx_per_s"] for r in night if r["cond"] == c and r["concurrency"] == k]
        b = [r["tx_per_s"] for r in bc if r["cond"] == c and r["setting"] == base and r["concurrency"] == k]
        if len(a) >= 2 and len(b) >= 2:
            p = stats.ttest_ind(a, b, equal_var=False).pvalue
            R["drift"][f"{c}_c{k}"] = {"main_mean": float(np.mean(a)), "main_n": len(a), "blockcut_mean": float(np.mean(b)), "blockcut_n": len(b),
                                      "change_pct": float(100 * (np.mean(b) / np.mean(a) - 1)), "welch_p": float(p)}
            print(f"   {NAMES[c]:10} c{k:<3} main {np.mean(a):6.1f} (n={len(a)})  block-cutting {np.mean(b):6.1f} (n={len(b)})  {100*(np.mean(b)/np.mean(a)-1):+5.1f}%  Welch p = {p:.3f}")

# ---------------------------------------------------------------- Table 11 SD
print("\n== 7b. Table 11 (block cutting) with SD: throughput mean ± CI (SD)")
R["table9_sd"] = {}
for c in ("mldsa44", "mldsa87"):
    for s in settings:
        row = []
        for k in (10, 20, 50):
            xs = np.array([r["tx_per_s"] for r in bc if r["cond"] == c and r["setting"] == s and r["concurrency"] == k])
            if len(xs) >= 2:
                m, lo, hi = ci_t(xs)
                R["table9_sd"][f"{c}_{s}_c{k}"] = {"n": len(xs), "mean": m, "ci_half": m - lo, "sd": float(xs.std(ddof=1))}
                row.append(f"{m:6.1f} ± {m-lo:4.1f} ({xs.std(ddof=1):4.1f})")
        print(f"   {NAMES[c]:10} {s:14} " + " | ".join(row))

# ---------------------------------------------------------------- Table 8 extra: p95 and share above batch timeout for ML-DSA-87 at 10 clients
print("\n== Table 8 extra: ML-DSA-87 at 10 clients, p95 and p99 per run")
xs = [(r["rep"], r["mean_ms"], r["p95_ms"], r["p99_ms"]) for r in night if r["cond"] == "mldsa87" and r["concurrency"] == 10]
R["mldsa87_c10"] = [{"rep": a, "mean_ms": b, "p95_ms": c_, "p99_ms": d} for a, b, c_, d in sorted(xs)]
print("   rep  mean   p95    p99")
for a, b, c_, d in sorted(xs):
    print(f"   {a:>3} {b:6.1f} {c_:6.1f} {d:6.1f}")
print(f"   means: mean {np.mean([x[1] for x in xs]):.1f}, p95 {np.mean([x[2] for x in xs]):.1f}, p99 {np.mean([x[3] for x in xs]):.1f}")

json.dump(R, open(OUT, "w"), indent=1)
print(f"\nwrote {OUT}")
