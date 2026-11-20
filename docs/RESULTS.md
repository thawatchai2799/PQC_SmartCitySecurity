# Results

Each results directory keeps its summaries (`summary*`, `environment.txt`, logs) as plain files and the
per-run files (benchmark outputs, decoded block files, container statistics, certificates, deploy logs
and the copies of the tools used) in `raw.zip`. Extract it in place before re-running a summary or a
figure script, for example:

```bash
cd results/night_20261022_0144 && unzip -q raw.zip && cd -
```

All paths below are given as they are after extraction.

## Repeated runs: `results/night_20261022_0144/`

Five conditions, ten repetitions each, in a new random order per repetition (50 runs, 200 benchmarks,
2 h 40 min). One benchmark (ML-DSA-65, repetition 9, 20 clients) lost a client worker to a gateway
error ("no combination of peers can be derived which satisfy the endorsement policy") and committed
1,955 of 2,000 transactions; it is excluded from the means, and the ledger size of that run is left
out of the ML-DSA-65 ledger mean (nine runs). Raw block files are not kept; their
decoded composition, for the first two block files of repetition 1 (the whole ECDSA ledger; for the
post-quantum conditions, the 20-client benchmark and the start of the 50-client one), is in
`<cond>/rep1/decode_blockfile_00000*.json`.

Regenerate every summary number and the figures:

```bash
python3 -I tools/summarize.py results/night_20261022_0144 --json results/night_20261022_0144/summary_stats.json
python3 figures/make_figures.py --night results/night_20261022_0144
```

| Result | Source in this directory | Produced by |
| --- | --- | --- |
| throughput and latency per condition and concurrency (mean, 95% CI) | `summary.csv` | `tools/summarize.py` |
| bytes per transaction by category, transactions per block | `<cond>/rep1/decode_blockfile_*.json` | `tools/decode_blockfile.py`, `tools/summarize.py` |
| ledger size after 4,001 alerts, yearly projection at 10 alerts/s | `<cond>/rep*/du_after_c20_c50.txt` | `tools/summarize.py` |
| container CPU per transaction at 50 clients | `<cond>/rep*/stats_c50.csv` | `tools/summarize.py` |
| certificate sizes (DER, PEM) and algorithms | `<cond>/rep1/certs.txt` | `scripts/night_run.sh` |
| figure 1, 2, 3 | all of the above | `figures/make_figures.py` |

`summary_tables.txt` and `summary_stats.json` hold the output of `tools/summarize.py` for this
directory.

## Headline numbers

| Condition | Bytes per transaction | Ledger after 4,001 alerts | tx/s at 20 clients | tx/s at 100 clients |
| --- | --- | --- | --- | --- |
| ECDSA | 5,468 | 24.25 MB | 170.0 +- 16.2 | 210.3 +- 26.3 |
| ML-DSA-44 | 32,824 (6.0x) | 134.08 MB (5.53x) | 134.3 +- 13.4 | 150.9 +- 19.9 |
| ML-DSA-65 | 44,152 (8.1x) | 179.37 MB (7.40x) | 101.1 +- 8.9 | 123.4 +- 11.3 |
| ML-DSA-87 | 59,483 (10.9x) | 240.50 MB (9.92x) | 78.5 +- 4.3 | 102.9 +- 7.3 |
| Hybrid-44 | 34,015 (6.2x) | 138.84 MB (5.73x) | 126.9 +- 12.1 | 142.7 +- 18.5 |

About 72% of every post-quantum transaction is the four certificates embedded in it (stored as PEM),
and about 22% is signatures. ML-DSA-87 transactions are large enough that the orderer's default
PreferredMaxBytes (512 KiB) cuts the decoded blocks at 8.5 transactions on average; this matches the
99th-percentile latency of about 2.08 s at 10 clients, just above the 2 s batch timeout.

## Block cutting and identity size: `results/blockcut_20261022_1109/`

Produced by `scripts/blockcut_run.sh` (65 runs, 3 h 18 min). Phase 1 ran each condition once; phase 2
ran ML-DSA-87 and ML-DSA-44 with three orderer settings, ten repetitions each in a new random order
per repetition (180 benchmarks, none excluded). Every run's genesis block held the intended
PreferredMaxBytes and BatchTimeout, and the ledger height was read around every benchmark.

```bash
python3 -I tools/summarize_blockcut.py results/blockcut_20261022_1109 --json results/blockcut_20261022_1109/summary_stats.json
```

ML-DSA-87 (mean ± 95% CI over 10 repetitions):

| Setting | Clients | tx/s | p99 latency (ms) | tx per block |
| --- | --- | --- | --- | --- |
| 512 KB, 2s (default) | 10 | 40.9 ± 2.2 | 2076 ± 14 | 8.43 |
| 1 MB, 2s | 10 | 82.9 ± 1.1 | 161 ± 3 | 10.00 |
| 512 KB, 500ms | 10 | 65.2 ± 2.9 | 578 ± 10 | 7.61 |
| 512 KB, 2s (default) | 20 | 80.6 ± 5.2 | 415 ± 51 | 8.73 |
| 1 MB, 2s | 20 | 90.7 ± 4.9 | 362 ± 16 | 9.95 |
| 512 KB, 500ms | 20 | 99.8 ± 3.5 | 375 ± 29 | 8.16 |

ML-DSA-44 blocks already hold ten transactions at 512 KB; its throughput and latency do not change
with the setting (see `summary_tables.txt`).

Identity size (block-file bytes per transaction without configuration blocks; DER and reference are
counterfactual rebuilds, compression is measured):

| Condition | PEM (stored) | DER | 32-byte reference | zstd -3 |
| --- | --- | --- | --- | --- |
| ECDSA | 5,464 | 4,246 | 1,577 | 456 |
| ML-DSA-44 | 32,732 | 26,289 | 8,869 | 7,815 |
| ML-DSA-65 | 43,971 | 35,314 | 11,624 | 10,601 |
| ML-DSA-87 | 59,155 | 47,612 | 15,781 | 14,943 |
| Hybrid-44 | 33,907 | 27,159 | 8,869 | 7,809 |

## TLS key exchange: `results/tls_20261022_160659/`

Produced by `scripts/tls_run.sh` (5 conditions, 4 endpoints, Go 1.27 and Node.js 24 / OpenSSL 3.5.6
clients, 50 handshakes per setting; 120 probe series, all completed). With default settings every
endpoint negotiated X25519MLKEM768 with both clients in every condition, and every endpoint also
accepted X25519MLKEM768 alone. Against X25519 alone, a hybrid handshake carried 1086 to 1090 more
bytes from the server and 1232 to 1234 more from the client, and took 0.1 to 0.7 ms longer (median
0.3 ms). The Fabric binaries in the images were built with Go 1.27.0 and carry no DefaultGODEBUG
overrides. Peer and orderer TLS certificates keep ECDSA keys but are signed by the condition's TLS CA,
so their chains grow from about 0.73 kB (ECDSA) to 3.1, 4.0 and 5.3 kB (ML-DSA-44, -65, -87) and
3.2 kB (hybrid); the CA server's own TLS certificate has an ML-DSA key in the pure ML-DSA conditions.

## Negative controls, node-to-node TLS, per-block compression, long and constrained-network runs: `results/revision_full_20261120_213228/`

Produced by `scripts/revision_run.sh full` (2 h 7 min; 37 fresh networks; no benchmark excluded; every
genesis block held the default orderer setting, 512 KiB and 2 s). `summary.csv` holds one row per
benchmark (`exp` A: the 20-client benchmark of the per-block compression ledgers; A_tls: the short
benchmark during the capture; B: the ten 10,000-alert chunks of each long run; C: the paired benchmarks
of the constrained-network runs, `net` = `none` or `wan`, `pos` = order within the network).
`summary_tables.txt` is the output of `tools/summarize_revision.py`; `stats/` holds the outputs of
`tools/revision_analysis.py` (derived numbers of this directory), `tools/revision_stats.py` (paired
statistics of the repeated runs and the block-cutting runs) and `tools/city_cost.py`.

```bash
cd results/revision_full_20261120_213228 && unzip -q raw.zip && unzip -q tls_captures.zip && cd -
python3 -I tools/summarize_revision.py results/revision_full_20261120_213228
python3 -I tools/revision_analysis.py results/revision_full_20261120_213228 /tmp/revision_analysis.json
python3 -I tools/revision_stats.py results/night_20261022_0144/summary.csv results/blockcut_20261022_1109/summary.csv /tmp/revision_stats.json
python3 -I tools/city_cost.py /tmp/city_cost.json
python3 figures/make_figures.py --night results/night_20261022_0144 --blockcut results/blockcut_20261022_1109 --revision results/revision_full_20261120_213228
```

| Result | Source in this directory | Produced by |
| --- | --- | --- |
| negative controls: stage, validation code and error of every tampered transaction | `A/<cond>/negctl.json` | `bench/negctl.mjs` |
| key-exchange group of every TLS connection on the bridge, by endpoint pair | `A/<cond>/tls_groups.json` (from `A/<cond>/tls.pcap` in `tls_captures.zip`) | `tools/tlshello.py` |
| per-block compression (gzip, zstd, zstd + certificate dictionary, trained dictionary) | `A/<cond>/blockcomp.json`, certificates in `A/<cond>/certs/` | `tools/blockcomp.py` |
| ledger components after every 10,000 alerts, throughput per chunk | `B/<cond>/ledger_growth.csv`, `B/<cond>/bench_chunk*.json` | `scripts/revision_run.sh` |
| constrained network: paired benchmarks, round trips, netem configuration | `C/<cond>/rep*/bench_{none,wan}.json`, `rtt.txt`, `netem.txt` | `scripts/revision_run.sh` |
| Figure 4 (long runs), individual runs in Figures 2 and 5 | all of the above and the earlier directories | `figures/make_figures.py` |

Headline numbers:

* Negative controls: 23 tampered transactions over the five conditions (flipped client, proposal and
  endorsement signatures; an endorsement by the other organisation's certificate claiming Org1MSP; a
  valid ML-DSA signature of the other parameter set; on Hybrid-44, a valid ECDSA signature by the
  classical subject key), every one rejected at the expected stage with the expected code (orderer
  FORBIDDEN, endorser "access denied", committer ENDORSEMENT_POLICY_FAILURE); the ten valid controls
  committed.
* Node-to-node TLS: every peer-to-orderer and peer-to-peer connection in every condition negotiated TLS
  1.3 with X25519MLKEM768 (server key share 1120 bytes).
* Per-block compression (bytes per transaction, saving): zstd -3 alone removes 67.7% to 70.5% of a
  post-quantum transaction per block; with a dictionary made of the channel's four certificates 75.1% to
  77.0% (7,808 to 14,761 bytes per ML-DSA-44 to ML-DSA-87 transaction); a trained dictionary 74.7% to
  76.6%.
* Long runs (100,000 alerts at 50 clients): ledger directory 5,782 (ECDSA) and 33,042 (ML-DSA-44) bytes
  per alert by least squares (R^2 0.99998 and 0.999999); block files 5,465 and 32,725 bytes per alert
  (R^2 1.000000), 94.0% and 98.9% of the final ledger (582 MB and 3.31 GB).
* Constrained network (20 ms round trip, 100 Mbit/s between nodes, 20 clients, 10 fresh networks per
  condition): throughput 173.8 -> 125.0 (ECDSA), 129.4 -> 92.8 (ML-DSA-44), 76.7 -> 50.3 (ML-DSA-87)
  transactions per second; geometric-mean ratios 0.72, 0.73 and 0.66; slower with the delay in all 30
  pairs.

The raw block files of the five per-block compression ledgers (339 MB, `A/<cond>/raw/`) are not in the
repository; the Zenodo archive of release v1.2 holds them as
`revision_full_20261120_213228_blockfiles.tar.zst`.

## Preliminary single runs: `results/preliminary/`

The first ECDSA and ML-DSA-44 runs, made by hand before the driver existed; kept for traceability.
