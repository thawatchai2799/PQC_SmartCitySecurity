# Preliminary single runs

One run per condition on the same host and build, before the repeated overnight runs.
They are kept for traceability; the paper reports the repeated runs.

| File | Content |
| --- | --- |
| `bench_ecdsa_c20.json`, `bench_ecdsa_c50.json` | ECDSA identities, 2,000 alerts at concurrency 20 and 50 |
| `bench_mldsa44_c20.json`, `bench_mldsa44_c50.json` | ML-DSA-44 identities, same protocol |
| `ledger_du.txt` | `du -sb` of the peer ledger directory and the number of anchored alerts |
| `decode_*.json` | byte composition of the peer block files (`tools/decode_blockfile.py`) |
| `cert_der_sizes_mldsa44.txt` | DER and PEM sizes of the ML-DSA-44 certificates |
| `bench_mldsa65_rep1.csv` | first ML-DSA-65 run of the overnight series (c20, c50) |

The ML-DSA-44 ledger holds 4,021 alerts (one CLI invoke, a 20-transaction smoke test and 4,000
benchmark transactions); its block files rolled over at 64 MiB, so both files are decoded.
