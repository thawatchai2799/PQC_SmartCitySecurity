"""City-level storage and cost figures for the revision (reviewer 2, city-level comment).

Bytes per alert: the ledger after 4001 alerts divided by 4001, mean over ten repetitions (Table 10 of the
paper), so that every figure here is consistent with Tables 8 and 11. The incremental growth between alert
4001 and 8001 is 0.6 to 0.7% lower (6025 / 33,289 / 44,529 / 59,738 / 34,467 B) and is reported in the
text as the stationarity check; it changes none of the rounded figures below.
Conventions, as in the paper: 1 TB = 10^12 B, 1 GiB = 2^30 B, 365.25-day year, provisioned capacity
billed per GiB-month. Cumulative cost over N years provisions each year's end-of-year capacity for
the whole year: cost(N) = yearly_cost x N(N+1)/2  (the convention that reproduces the reviewer's
USD 0.52 M / 0.93 M / 0.09 M figures). The alternative, continuous provisioning, gives N^2/2 instead.
"""
import json
import sys

BPA = {"ECDSA": 6061, "ML-DSA-44": 33512, "ML-DSA-65": 44831, "ML-DSA-87": 60110, "Hybrid-44": 34701}
YEAR_S = 365.25 * 86400
PRICES = {"gp3 SSD (AWS EBS, US East)": 0.08, "st1 HDD (AWS EBS)": 0.045, "S3 Standard": 0.023, "sc1 cold HDD (AWS EBS)": 0.015}
out = {}

print("== Storage per million alerts (rate-independent) and per year at 1 / 10 / 100 alerts per second")
print(f"{'cond':10} {'B/alert':>8} {'GB per 10^6 alerts':>18} {'TB/yr @1/s':>11} {'TB/yr @10/s':>12} {'TB/yr @100/s':>13}")
for c, b in BPA.items():
    row = {"bytes_per_alert": b, "GB_per_million": b * 1e6 / 1e9, "TB_per_year": {r: b * r * YEAR_S / 1e12 for r in (1, 10, 100)}}
    out[c] = row
    print(f"{c:10} {b:8d} {row['GB_per_million']:18.1f} {row['TB_per_year'][1]:11.2f} {row['TB_per_year'][10]:12.1f} {row['TB_per_year'][100]:13.0f}")

print("\n== Yearly provisioned cost per peer at 10 alerts per second (USD, 1 GiB = 2^30 B), by storage price; Table 15 gives the monthly figure = yearly / 12")
print(f"{'cond':10} " + " ".join(f"{p:>12.3f}" for p in PRICES.values()) + "   (USD per GiB-month)")
for c, b in BPA.items():
    gib = b * 10 * YEAR_S / 2**30
    out[c]["GiB_per_year_10ps"] = gib
    out[c]["yearly_cost_10ps"] = {k: gib * 12 * p for k, p in PRICES.items()}
    print(f"{c:10} " + " ".join(f"{gib*12*p:12.0f}" for p in PRICES.values()))

print("\n== Cumulative provisioned cost per peer over a retention period, 10 alerts per second, gp3 price (USD thousand)")
print("   cost(N) = yearly x N(N+1)/2 ; in brackets: continuous provisioning, yearly x N^2/2")
print(f"{'cond':10} " + " ".join(f"{n:>14d} y" for n in (5, 10, 20)))
for c, b in BPA.items():
    y = out[c]["yearly_cost_10ps"]["gp3 SSD (AWS EBS, US East)"]
    out[c]["cumulative_gp3_10ps"] = {n: y * n * (n + 1) / 2 for n in (5, 10, 20)}
    print(f"{c:10} " + " ".join(f"{y*n*(n+1)/2/1e3:10.0f} ({y*n*n/2/1e3:4.0f})" for n in (5, 10, 20)))

print("\n== Network-wide, 10 alerts per second, 10-year retention, gp3: every peer and orderer keeps the block files")
print("   (orderers keep no state or history database; block files are 98% of a post-quantum ledger, so the same figure is used)")
configs = {"test network (2 peers + 1 orderer)": 3, "5 agencies x 1 peer + 3 orderers": 8, "5 agencies x 2 peers + 3 orderers": 13, "10 agencies x 2 peers + 5 orderers": 25}
print(f"{'cond':10} " + " ".join(f"{n:>8d} nodes" for n in configs.values()) + "   (USD million)")
for c, b in BPA.items():
    ten = out[c]["cumulative_gp3_10ps"][10]
    out[c]["network_10y_gp3_musd"] = {k: ten * n / 1e6 for k, n in configs.items()}
    print(f"{c:10} " + " ".join(f"{ten*n/1e6:14.2f}" for n in configs.values()))
print("   configurations: " + "; ".join(f"{n} = {k}" for k, n in configs.items()))

print("\n== Ratios to ECDSA (storage and cost scale together; price cancels)")
e = BPA["ECDSA"]
for c, b in BPA.items():
    print(f"   {c:10} {b/e:5.2f} x ECDSA")

json.dump(out, open(sys.argv[1] if len(sys.argv) > 1 else "city_calc.json", "w"), indent=1)
