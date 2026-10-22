# Analysis

## Byte composition of the ledger

```bash
python3 -I tools/decode_blockfile.py blockfile_000000 --json decode.json
```

The decoder reads the peer's block file record by record (`[varint length][block]`) and walks the
protobuf fields of every block, assigning each byte to one of twelve categories:

| Category | What it holds |
| --- | --- |
| `payload_header` | channel header and the client's SerializedIdentity (certificate) |
| `action_header` | the client's SerializedIdentity again, in the chaincode action |
| `endorser_cert` | each endorser's SerializedIdentity |
| `endorser_signature` | each endorser's signature |
| `envelope_signature` | the client's signature over the payload |
| `block_metadata` | orderer signature and identity, validity flags, commit hash |
| `proposal_payload` | chaincode name, function and arguments (the alert) |
| `proposal_hash`, `rwset`, `response_events_ccid` | proposal hash, read/write set, response |
| `block_header`, `config_envelope_bytes` | block hashes, configuration transactions |
| framing | protobuf tags and lengths, file length prefixes |

When a ledger grows past 64 MiB the peer starts `blockfile_000001`; decode every file of the
ledger and add the categories up (the figure script does this).

## Figures

```bash
pip install -r requirements.txt
python3 figures/make_figures.py                                    # results/preliminary
python3 figures/make_figures.py --night results/night_YYYYMMDD_HHMM  # repeated runs
```

| Output (`figures/out/`) | Content |
| --- | --- |
| `fig1_transaction_anatomy` | parts of one committed transaction, bytes for ECDSA and ML-DSA-44 |
| `fig2_throughput` | throughput and mean latency against concurrency, mean and 95% confidence interval per condition |
| `fig3_bytes_per_transaction` | bytes per transaction by category, per condition |

Every figure is written as PDF (vector) and PNG at 600 dpi.

## Summary statistics

`summary.csv` has one row per benchmark. Group by `cond` and `concurrency` and report the mean
with a 95% confidence interval from the t distribution over repetitions. Rows with `n_tx` of 0 or
`failed_workers` above 0 mark failed benchmarks and are excluded from the means.

## Block cutting and identity size

```bash
python3 -I tools/summarize_blockcut.py results/blockcut_20261022_1109
python3 figures/make_figures.py --night results/night_20261022_0144 --blockcut results/blockcut_20261022_1109
```

The second command also writes `fig4_block_cutting` (throughput and 99th-percentile latency of
ML-DSA-87 and ML-DSA-44 under three orderer settings) and `fig5_identity_encoding` (bytes per
transaction as stored, rebuilt with DER or 32-byte identity references, and compressed).
