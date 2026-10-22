#!/usr/bin/env python3
"""Make the figures as PDF (vector) and PNG (600 dpi).

Usage (from the repository root):
    python3 figures/make_figures.py                       # preliminary single runs
    python3 figures/make_figures.py --night results/night_YYYYMMDD_HHMM [--blockcut results/blockcut_YYYYMMDD_HHMM]

Inputs
    --prelim DIR   results/preliminary (decode_*.json, bench_*_c*.json, bench_mldsa65_rep1.csv)
    --night DIR    an overnight result directory written by scripts/night_run.sh
                   (summary.csv and <cond>/rep*/decode_blockfile_00000*.json)
    --blockcut DIR a result directory written by scripts/blockcut_run.sh
                   (summary.csv and identity_size/<cond>/identity_size.json)
Outputs (figures/out/)
    fig1_transaction_anatomy.{pdf,png}
    fig2_throughput.{pdf,png}      (with --night: throughput and mean latency panels)
    fig3_bytes_per_transaction.{pdf,png}
    fig4_block_cutting.{pdf,png}       (with --blockcut)
    fig5_identity_encoding.{pdf,png}   (with --blockcut)
"""
import argparse
import csv
import glob
import json
import math
import os
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                      # noqa: E402
from matplotlib.patches import FancyBboxPatch        # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "out")

COND_ORDER = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]
COND_LABEL = {"ecdsa": "ECDSA", "hybrid44": "Hybrid-44",
              "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87"}
COND_COLOR = {"ecdsa": "#4d4d4d", "hybrid44": "#8c6bb1", "mldsa44": "#2166ac",
              "mldsa65": "#4393c3", "mldsa87": "#92c5de"}
# Byte categories of tools/decode_blockfile.py, grouped for the figures
GROUPS = [
    ("Identity fields (client x2, endorsers x2)", ["payload_header", "action_header", "endorser_cert"], "#c0504d"),
    ("Signatures (client, endorsers x2)", ["envelope_signature", "endorser_signature"], "#f2a65a"),
    ("Block metadata (orderer certificate and signature)", ["block_metadata"], "#9bbb59"),
    ("Application data (alert, read/write set, response, hash)",
     ["proposal_payload", "proposal_hash", "rwset", "response_events_ccid"], "#4f81bd"),
    ("Block header, configuration, framing", ["block_header", "config_envelope_bytes", "_framing"], "#bfbfbf"),
]

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.titlesize": 9,
                     "axes.labelsize": 8, "legend.fontsize": 7, "pdf.fonttype": 42, "ps.fonttype": 42})


def num(v, d=0):
    """Number as in the paper: no thousands separator below 10,000, a comma from 10,000."""
    s = f"{v:,.{d}f}"
    return s.replace(",", "") if abs(v) < 10000 else s


def save(fig, name):
    os.makedirs(OUT, exist_ok=True)
    fig.savefig(os.path.join(OUT, name + ".pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=600, bbox_inches="tight")
    plt.close(fig)
    print("wrote", name + ".pdf/.png")


# ------------------------------------------------------------------ data loading
def load_decodes(paths):
    """Merge one or more decode JSONs (the block files of one ledger) into per-transaction bytes."""
    tot, tx, fbytes, blocks = {}, 0, 0, 0
    for p in paths:
        d = json.load(open(p))
        for k, v in d["bytes"].items():
            tot[k] = tot.get(k, 0) + v
        tot["_framing"] = tot.get("_framing", 0) + d["framing_bytes"] + d["length_prefix_bytes"]
        tx += d["transactions"]
        fbytes += d["file_bytes"]
        blocks += d["blocks"]
    per_tx = {k: v / tx for k, v in tot.items()}
    return {"per_tx": per_tx, "file_per_tx": fbytes / tx, "tx": tx, "blocks": blocks}


def decodes_from(prelim, night):
    out = {}
    if night:
        for cond in COND_ORDER:
            reps = sorted(glob.glob(os.path.join(night, cond, "rep*")))
            for r in reps:
                files = sorted(glob.glob(os.path.join(r, "decode_blockfile_00000*.json")))
                if files:
                    out[cond] = load_decodes(files)
                    break
    if not out:
        out["ecdsa"] = load_decodes([os.path.join(prelim, "decode_ecdsa_blockfile_000000.json")])
        out["mldsa44"] = load_decodes(sorted(glob.glob(os.path.join(prelim, "decode_mldsa44_blockfile_*.json"))))
    return out


def throughput_from(prelim, night, metric="tx_per_s"):
    """Return {cond: {conc: [values]}} for one column of summary.csv.
    Benchmarks with a failed worker (fewer than all transactions committed) are excluded."""
    data = {}
    if night and os.path.exists(os.path.join(night, "summary.csv")):
        for row in csv.DictReader(open(os.path.join(night, "summary.csv"))):
            try:
                v = float(row[metric])
            except ValueError:
                continue
            if int(row["n_tx"]) <= 0 or row["failed_workers"] != "0" or math.isnan(v):
                continue
            data.setdefault(row["cond"], {}).setdefault(int(row["concurrency"]), []).append(v)
        return data, False
    for cond in ["ecdsa", "mldsa44"]:
        for c in (20, 50):
            r = json.load(open(os.path.join(prelim, f"bench_{cond}_c{c}.json")))
            data.setdefault(cond, {}).setdefault(c, []).append(r["tx_per_s"])
    p = os.path.join(prelim, "bench_mldsa65_rep1.csv")
    if os.path.exists(p):
        for row in csv.DictReader(open(p)):
            data.setdefault(row["cond"], {}).setdefault(int(row["concurrency"]), []).append(float(row["tx_per_s"]))
    return data, True


def mean_ci(vals):
    m = statistics.mean(vals)
    if len(vals) < 2:
        return m, 0.0
    # two-sided 95% t quantiles for small n
    t = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262,
         11: 2.228, 12: 2.201, 13: 2.179, 14: 2.160, 15: 2.145}
    q = t.get(len(vals), 1.96)
    return m, q * statistics.stdev(vals) / math.sqrt(len(vals))


# ------------------------------------------------------------------ figure 1
def fig1(dec):
    """Anatomy of one committed transaction, bytes per transaction for ECDSA and ML-DSA-44."""
    e, m = dec["ecdsa"]["per_tx"], dec.get("mldsa44", dec["ecdsa"])["per_tx"]
    lab2 = "ML-DSA-44" if "mldsa44" in dec else "ECDSA"

    def b(keys, src):
        return sum(src.get(k, 0) for k in keys)

    fig, ax = plt.subplots(figsize=(7.0, 5.0))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 75)
    ax.axis("off")

    def box(x, y, w, h, title, keys=None, fc="#ffffff", ec="#404040", lw=0.8, crypto=False, note=None):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=0.8",
                                    fc=fc, ec=ec, lw=lw))
        ax.text(x + 1.0, y + h - 1.4, title, fontsize=7.2, weight="bold" if crypto else "normal",
                va="top", ha="left", color="#202020")
        if note:
            ax.text(x + 1.0, y + h - 4.6, note, fontsize=6.3, va="top", ha="left", color="#505050")
        if keys is not None:
            if lab2 != "ECDSA":
                txt = f"{num(b(keys, e))} B  \u2192  {num(b(keys, m))} B"
            else:
                txt = f"{num(b(keys, e))} B"
            ax.text(x + w - 1.0, y + 0.9, txt, fontsize=7, ha="right", va="bottom",
                    color="#b2182b" if crypto else "#303030", weight="bold" if crypto else "normal")

    cert = "#fde0dd"
    sig = "#fee8c8"
    app = "#deebf7"
    box(1, 1, 98, 73, "Block (stored on every peer)", fc="#fafafa", ec="#808080")
    box(3, 14, 94, 55, "Transaction envelope (one per transaction)", fc="#ffffff")
    box(5, 54, 43, 10, "Payload header", ["payload_header"], fc=cert, crypto=True,
        note="channel header + client identity (PEM)")
    box(51, 54, 44, 10, "Action header", ["action_header"], fc=cert, crypto=True,
        note="client identity again (PEM)")
    box(5, 42, 43, 10, "Proposal payload", ["proposal_payload"], fc=app,
        note="chaincode, function, the alert itself")
    box(51, 42, 44, 10, "Proposal response payload", ["proposal_hash", "rwset", "response_events_ccid"], fc=app,
        note="proposal hash, read/write set, response")
    box(5, 30, 90, 10, "Endorser identities (peer0.org1, peer0.org2)", ["endorser_cert"], fc=cert, crypto=True,
        note="two PEM certificates, one per endorsing organisation")
    box(5, 17, 43, 10, "Endorser signatures (x2)", ["endorser_signature"], fc=sig, crypto=True)
    box(51, 17, 44, 10, "Envelope signature (client)", ["envelope_signature"], fc=sig, crypto=True)
    box(3, 3, 94, 9, "Block metadata (share per transaction)", ["block_metadata"], fc="#e5f0d5", crypto=True,
        note="orderer signature and identity, transaction validity flags")
    tot_e, tot_m = dec["ecdsa"]["file_per_tx"], dec.get("mldsa44", dec["ecdsa"])["file_per_tx"]
    ax.set_title(f"Bytes per committed transaction in the peer block file: ECDSA \u2192 {lab2} "
                 f"(total {num(tot_e)} B \u2192 {num(tot_m)} B)", fontsize=8.5, loc="left")
    save(fig, "fig1_transaction_anatomy")


# ------------------------------------------------------------------ figure 3 (bytes)
def fig_bytes(dec):
    conds = [c for c in COND_ORDER if c in dec]
    fig, ax = plt.subplots(figsize=(7.0, 0.55 * len(conds) + 1.5))
    y = list(range(len(conds)))[::-1]
    for gi, (gname, keys, color) in enumerate(GROUPS):
        left = []
        for c in conds:
            pt = dec[c]["per_tx"]
            left.append(sum(sum(pt.get(k, 0) for k in g[1]) for g in GROUPS[:gi]) / 1000)
        widths = [sum(dec[c]["per_tx"].get(k, 0) for k in keys) / 1000 for c in conds]
        ax.barh(y, widths, left=left, color=color, edgecolor="white", linewidth=0.5, height=0.62, label=gname)
    for yi, c in zip(y, conds):
        tot = dec[c]["file_per_tx"] / 1000
        pt = dec[c]["per_tx"]
        certs = sum(pt.get(k, 0) for k in GROUPS[0][1]) / dec[c]["file_per_tx"] * 100
        sigs = sum(pt.get(k, 0) for k in GROUPS[1][1]) / dec[c]["file_per_tx"] * 100
        ax.text(tot + 0.4, yi, f"{tot:.1f} kB  (identity fields {certs:.0f}%, signatures {sigs:.0f}%)",
                va="center", fontsize=7)
    ax.set_yticks(y)
    ax.set_yticklabels([COND_LABEL[c] for c in conds])
    ax.set_xlabel("Block-file bytes per committed transaction (kB)")
    xmax = max(dec[c]["file_per_tx"] for c in conds) / 1000
    ax.set_xlim(0, xmax * 1.45)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.11 - 0.25 / len(conds)), ncol=2, frameon=False)
    save(fig, "fig3_bytes_per_transaction")


# ------------------------------------------------------------------ figure 2 (throughput)
def fig_throughput(tp, preliminary, lat=None):
    """Throughput (and, with repeated runs, mean latency) against concurrency."""
    panels = [("Committed transactions per second", tp)]
    if lat:
        panels.append(("Mean latency (ms)", lat))
    fig, axes = plt.subplots(1, len(panels), figsize=(3.6 * len(panels) + 0.6, 3.0), squeeze=False)
    for i, (ax, (ylabel, data)) in enumerate(zip(axes[0], panels)):
        for c in COND_ORDER:
            if c not in data:
                continue
            xs = sorted(data[c])
            ms, cis = zip(*[mean_ci(data[c][x]) for x in xs])
            ax.errorbar(xs, ms, yerr=cis, marker="o", ms=3.5, lw=1.2, capsize=2.5,
                        color=COND_COLOR[c], label=COND_LABEL[c])
        ax.set_xlabel("Concurrent clients")
        ax.set_ylabel(ylabel)
        ax.set_xscale("log")
        allx = sorted({x for c in data for x in data[c]})
        ax.set_xticks(allx)
        ax.set_xticklabels([str(x) for x in allx])
        ax.minorticks_off()
        ax.set_ylim(bottom=0)
        ax.grid(axis="y", lw=0.4, color="#dddddd")
        ax.spines[["top", "right"]].set_visible(False)
        if len(panels) > 1:
            ax.set_title("(" + "ab"[i] + ")", fontsize=8.5, loc="left")
    axes[0][0].legend(frameon=False, fontsize=6.8)
    if preliminary:
        axes[0][0].set_title("Preliminary: one run per point", fontsize=7.5, loc="left", color="#606060")
    fig.tight_layout()
    save(fig, "fig2_throughput")


# ------------------------------------------------------------------ figure 4 (block cutting)
SETTINGS = [("pmb512k_bt2s", "512 KB, 2 s (default)", "#7f7f7f"),
            ("pmb1m_bt2s", "1 MB, 2 s", "#2166ac"),
            ("pmb512k_bt500ms", "512 KB, 500 ms", "#f2a65a")]


def fig_block_cutting(bc):
    """Throughput and 99th-percentile latency per orderer setting, ML-DSA-87 and ML-DSA-44."""
    data = {}
    for row in csv.DictReader(open(os.path.join(bc, "summary.csv"))):
        if row["phase"] != "main" or int(row["n_tx"]) <= 0 or row["failed_workers"] != "0":
            continue
        for m in ("tx_per_s", "p99_ms"):
            data.setdefault((row["cond"], row["setting"], int(row["concurrency"]), m), []).append(float(row[m]))
    concs = [10, 20, 50]
    fig, axes = plt.subplots(2, 2, figsize=(7.2, 5.0), sharex=True)
    for ri, cond in enumerate(["mldsa87", "mldsa44"]):
        for ci, (m, ylab) in enumerate([("tx_per_s", "Committed transactions per second"),
                                        ("p99_ms", "99th-percentile latency (ms)")]):
            ax = axes[ri][ci]
            w = 0.26
            for si, (s, lab, col) in enumerate(SETTINGS):
                ms, cis = [], []
                for c in concs:
                    mm, cc = mean_ci(data[(cond, s, c, m)])
                    ms.append(mm); cis.append(cc)
                xs = [i + (si - 1) * w for i in range(len(concs))]
                ax.bar(xs, ms, width=w, color=col, edgecolor="white", linewidth=0.5, label=lab,
                       yerr=cis, capsize=2, error_kw={"lw": 0.7})
                if m == "p99_ms":
                    for x, v in zip(xs, ms):
                        ax.text(x, v * 1.12, num(v), ha="center", va="bottom", fontsize=5.8)
            if m == "p99_ms":
                ax.set_yscale("log")
                ax.set_ylim(50, 4000)
            else:
                ax.set_ylim(0, 200)
            ax.set_xticks(range(len(concs)))
            ax.set_xticklabels([str(c) for c in concs])
            if ri == 1:
                ax.set_xlabel("Concurrent clients")
            ax.set_ylabel(ylab)
            ax.grid(axis="y", lw=0.4, color="#dddddd")
            ax.set_axisbelow(True)
            ax.spines[["top", "right"]].set_visible(False)
            ax.set_title(f"({'abcd'[2 * ri + ci]}) {COND_LABEL[cond]}", fontsize=8.5, loc="left")
    axes[0][0].legend(frameon=False, fontsize=6.8, title="PreferredMaxBytes, BatchTimeout", title_fontsize=6.8)
    fig.tight_layout()
    save(fig, "fig4_block_cutting")


# ------------------------------------------------------------------ figure 5 (identity encoding)
ENCODINGS = [("pem", "Stored (PEM)", "#c0504d"), ("der", "DER (rebuilt)", "#f2a65a"),
             ("ref", "32-byte reference (rebuilt)", "#9bbb59"), ("gzip6", "gzip -6 (measured)", "#bfbfbf"),
             ("zstd3", "zstd -3 (measured)", "#4f81bd")]


def fig_identity_encoding(bc):
    conds = [c for c in COND_ORDER if os.path.exists(os.path.join(bc, "identity_size", c, "identity_size.json"))]
    js = {c: json.load(open(os.path.join(bc, "identity_size", c, "identity_size.json"))) for c in conds}
    encs = [e for e in ENCODINGS if all(e[0] in js[c] for c in conds)]
    fig, ax = plt.subplots(figsize=(7.0, 0.75 * len(conds) + 1.4))
    h = 0.8 / len(encs)
    for ei, (k, lab, col) in enumerate(encs):
        ys = [len(conds) - 1 - i + (len(encs) / 2 - ei - 0.5) * h for i in range(len(conds))]
        vals = [js[c][k]["per_tx"] / 1000 for c in conds]
        ax.barh(ys, vals, height=h * 0.92, color=col, label=lab)
        for y, v in zip(ys, vals):
            ax.text(v + 0.4, y, f"{v:.1f}", va="center", fontsize=5.8)
    ax.set_yticks(range(len(conds)))
    ax.set_yticklabels([COND_LABEL[c] for c in conds][::-1])
    ax.set_xlabel("Block-file bytes per committed transaction (kB), configuration blocks left out")
    ax.set_xlim(0, max(js[c]["pem"]["per_tx"] for c in conds) / 1000 * 1.12)
    ax.grid(axis="x", lw=0.4, color="#dddddd")
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="lower right", frameon=False, fontsize=6.8)
    fig.tight_layout()
    save(fig, "fig5_identity_encoding")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prelim", default=os.path.join(ROOT, "results", "preliminary"))
    ap.add_argument("--night", default=None)
    ap.add_argument("--blockcut", default=None)
    a = ap.parse_args()
    dec = decodes_from(a.prelim, a.night)
    fig1(dec)
    tp, prelim = throughput_from(a.prelim, a.night)
    lat = None if prelim else throughput_from(a.prelim, a.night, "mean_ms")[0]
    fig_throughput(tp, prelim, lat)
    fig_bytes(dec)
    if a.blockcut:
        fig_block_cutting(a.blockcut)
        fig_identity_encoding(a.blockcut)


if __name__ == "__main__":
    main()
