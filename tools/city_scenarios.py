#!/usr/bin/env python3
"""Scale the measured results to city scenarios (storage, cost, larger application records).

Usage: python3 tools/city_scenarios.py results/night_YYYYMMDD_HHMM [--blockcut results/blockcut_YYYYMMDD_HHMM] [--price 0.08]

1. Ledger growth per peer per year at 1, 10 and 100 alerts per second, from the mean ledger size after 4001
   alerts (summary_stats.json of tools/summarize.py), and the monthly block-storage cost that one year of
   ledger adds at 10 alerts per second, at --price USD per GiB-month.
2. With --blockcut: ledger growth at 10 alerts per second if identities were referred to or the block files
   stored with zstd, applying the block-file savings of the identity-size runs to the block-file share of the
   ledger directory (block files over du of the ledger directory at the end of run 1) and leaving the rest
   unchanged.
3. Block-file bytes per transaction for larger application records: the fixed cryptographic part of the
   decoded block files (everything except the application-data categories) plus the application data.
"""
import json
import os
import sys

YEAR_S = 365.25 * 24 * 3600
CONDS = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "hybrid44"]
APP = ["proposal_payload", "proposal_hash", "rwset", "response_events_ccid"]
IDENT = ["payload_header", "action_header", "endorser_cert"]


def share_of_blockfiles(d, c):
    rep = os.path.join(d, c, "rep1")
    bf = sum(int(l.split()[4]) for l in open(os.path.join(rep, "blockfiles_ls.txt")) if "blockfile_" in l)
    du = int(open(os.path.join(rep, "du_end.txt")).read().split()[0])
    return bf / du


def main(d, price, bc=None):
    j = json.load(open(os.path.join(d, "summary_stats.json")))
    print(f"ledger growth per peer (TB per year) and monthly cost per year of ledger at 10 alerts/s (USD {price}/GiB-month)")
    for c in CONDS:
        per_alert = j["ledger"][c]["mean_bytes"] / 4001
        tb = [per_alert * r * YEAR_S / 1e12 for r in (1, 10, 100)]
        usd = tb[1] * 1e12 / 2 ** 30 * price
        print(f"  {c:9s} {per_alert / 1000:5.1f} kB/alert  " + "  ".join(f"{t:7.2f}" for t in tb) + f"   USD {usd:6.0f}")
    if bc:
        print("\nledger growth at 10 alerts/s (TB per year) with identity references or zstd-compressed block files")
        for c in CONDS:
            g = j["ledger"][c]["mean_bytes"] / 4001 * 10 * YEAR_S / 1e12
            s = share_of_blockfiles(d, c)
            ids = json.load(open(os.path.join(bc, "identity_size", c, "identity_size.json")))
            out = []
            for k in ("ref", "zstd3"):
                if k in ids:
                    r = 1 - ids[k]["per_tx"] / ids["pem"]["per_tx"]
                    out.append(f"{k} {g * (s * (1 - r) + (1 - s)):5.2f}")
            print(f"  {c:9s} stored {g:6.2f}  block-file share {100 * s:4.1f}%  " + "  ".join(out))
    print("\nblock-file bytes per transaction with larger application records (kB, ratio to ECDSA, identity share)")
    fixed, ident = {}, {}
    for c in CONDS:
        b = j["bytes"][c]
        cat = b["categories"]
        fixed[c] = b["per_tx"] - sum(cat.get(k, 0) for k in APP)
        ident[c] = sum(cat.get(k, 0) for k in IDENT)
    app0 = sum(j["bytes"]["ecdsa"]["categories"].get(k, 0) for k in APP)
    for a in (app0, 2000, 5000, 10000, 50000):
        row = []
        for c in CONDS:
            tot = fixed[c] + a
            row.append(f"{c} {tot / 1000:.1f} (x{tot / (fixed['ecdsa'] + a):.1f}, {100 * ident[c] / tot:.0f}%)")
        print(f"  app {a / 1000:5.2f} kB: " + "; ".join(row))


if __name__ == "__main__":
    a = sys.argv[1:]
    price, bc = 0.08, None
    if "--price" in a:
        i = a.index("--price"); price = float(a[i + 1]); a = a[:i] + a[i + 2:]
    if "--blockcut" in a:
        i = a.index("--blockcut"); bc = a[i + 1]; a = a[:i] + a[i + 2:]
    main(a[0], price, bc)
