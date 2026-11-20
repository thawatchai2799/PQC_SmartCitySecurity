# Post-quantum identities on Hyperledger Fabric: measured ledger cost

This repository measures what it costs to move every identity of a Hyperledger Fabric network
(certificate authorities, peers, orderer, administrators and clients) from ECDSA to the NIST
post-quantum signature standard ML-DSA (FIPS 204), on an alert-anchoring workload taken from a
smart-city security architecture.

It contains the driver that runs the experiment unattended, the benchmark client, the chaincode,
a decoder that attributes every byte of a Fabric peer block file to its source, the figure scripts,
and the results.

| Condition | MSP identities | Channel capability |
| --- | --- | --- |
| `ecdsa` | ECDSA P-256 | V3_0 |
| `mldsa44`, `mldsa65`, `mldsa87` | ML-DSA at NIST categories 2, 3 and 5 | V3_0 |
| `hybrid44` | ECDSA certificate carrying an ML-DSA-44 alternative key and signature | V3_0_HYBRID |

Each run builds a fresh two-organisation network (one peer per organisation, one Raft orderer,
Fabric CA), deploys the chaincode as an external service, and submits 2,000 `AnchorAlert`
transactions at each of 20, 50, 10 and 100 concurrent clients. Conditions are run in a new random
order in every repetition.

## Layout

| Path | Content |
| --- | --- |
| `scripts/night_run.sh` | unattended driver: all conditions, repeated, with progress and ETA |
| `bench/bench_night.mjs` | benchmark client (Fabric Gateway, ML-DSA or ECDSA signing) |
| `chaincode/` | CityAnchor chaincode and its external-service Dockerfile |
| `tools/decode_blockfile.py` | byte composition of a peer block file (no dependencies) |
| `scripts/blockcut_run.sh` | second driver: identity-size estimate, then block-cutting settings, repeated |
| `tools/block_sizes.py` | transactions and bytes of every block in a peer block file |
| `tools/mitigation_estimate.py` | block file rebuilt with identities as DER or 32-byte references, and compressed |
| `tools/summarize_blockcut.py` | summary tables of a `blockcut_*` results directory |
| `scripts/tls_run.sh` | TLS key exchange negotiated by the nodes and the client, per condition |
| `tools/tlsprobe/`, `tools/tls_probe_node.mjs`, `tools/summarize_tls.py` | Go and Node.js TLS probes and their summary |
| `scripts/revision_run.sh` | fourth driver: negative controls, node-to-node TLS capture, per-block compression, 100,000-alert runs and constrained-network runs |
| `bench/negctl.mjs` | negative-control client: tampered client, proposal and endorsement signatures, foreign and classical keys |
| `tools/tlshello.py` | key-exchange groups of every TLS connection in a packet capture (no dependencies) |
| `tools/blockcomp.py` | per-block compression of a block file: gzip, zstd, zstd with a certificate dictionary, trained dictionary |
| `tools/summarize_revision.py` | summary tables of a `revision_*` results directory |
| `tools/revision_stats.py`, `tools/revision_analysis.py`, `tools/city_cost.py` | paired statistics of the repeated runs, derived numbers of the revision run, city-level cost scenarios |
| `tools/check_embedded.sh` | checks that the copies embedded in the drivers match the files here |
| `setup/` | build the forks, prepare fabric-samples, install the workload |
| `figures/make_figures.py` | figures as PDF and 600 dpi PNG |
| `results/blockcut_20261022_1109/` | block-cutting settings and identity-size estimate (see `docs/RESULTS.md`) |
| `results/night_20261022_0144/` | ten repetitions of every condition (see `docs/RESULTS.md`) |
| `results/tls_20261022_160659/` | TLS key exchange per condition, endpoint and client (see `docs/RESULTS.md`) |
| `results/revision_full_20261120_213228/` | negative controls, node-to-node TLS, per-block compression, long runs, constrained network (see `docs/RESULTS.md`) |
| `results/preliminary/` | first single runs, kept for traceability |
| `tools/summarize.py` | means, confidence intervals, byte composition, ledger growth, CPU per transaction |
| `docs/` | setup, running, analysis, results and troubleshooting guides |

## Quick start

```bash
# 1. build the post-quantum forks and tag their images :pqc   (docs/SETUP.md)
bash setup/build_forks.sh
bash setup/setup_fabric_samples.sh
bash setup/install_workload.sh

# 2. run every condition, repeated, unattended                (docs/RUNNING.md)
cp scripts/night_run.sh ~/pqc/
setsid nohup bash ~/pqc/night_run.sh > ~/pqc/night_console.log 2>&1 &
cat ~/pqc/night_status.txt                                   # progress, remaining time, expected finish

# 3. figures from the results                                  (docs/ANALYSIS.md)
python3 figures/make_figures.py --night ~/pqc/results/night_YYYYMMDD_HHMM

# 4. negative controls, TLS capture, per-block compression, long and constrained-network runs (about 2 h)
cp scripts/revision_run.sh ~/pqc/
bash ~/pqc/revision_run.sh check && setsid nohup bash ~/pqc/revision_run.sh full > ~/pqc/revision_console.log 2>&1 &
```

## Releases

* v1.1: the repeated runs, the block-cutting and identity-size experiment and the TLS probes.
* v1.2: adds `scripts/revision_run.sh` and its results (`results/revision_full_20261120_213228/`): negative
  controls that tamper with signatures and identities, a capture of the key exchange between the nodes,
  per-block compression with and without a certificate dictionary, two 100,000-alert runs and a
  constrained-network experiment (20 ms round trip, 100 Mbit/s between nodes); paired statistics of the
  repeated runs; city-level cost scenarios; Figures 2 and 5 with individual runs and the new Figure 4.
  The raw block files of the per-block compression ledgers (339 MB) are in the Zenodo archive of this
  release only.

## Requirements

* Linux or WSL 2 with Docker Engine and Docker Compose v2
* Go 1.27 (the forks use `crypto/mldsa`)
* Node.js 24 with OpenSSL 3.5 or later (ML-DSA signing in the client)
* Python 3.9+ (decoder: standard library only; figures: `matplotlib`, `pillow`; statistics: `numpy`, `scipy`)
* `zstd` command-line tool (per-block compression), and the `nicolaka/netshoot` image for the packet capture and traffic shaping of `scripts/revision_run.sh`
* about 10 GB of free disk for images and ledgers

## Software used

* Hyperledger Fabric fork with ML-DSA identities in the MSP:
  https://github.com/ufrn-itau-crypto-quantum/fabric (with `fabric-lib-go`, branch `composite-mldsa`)
* Fabric CA fork: https://github.com/ufrn-itau-crypto-quantum/fabric-ca (branch `certificate-chain`)
* fabric-samples test network: https://github.com/hyperledger/fabric-samples

The exact commits are written to `environment.txt` in every results directory.

## License

MIT, see `LICENSE`.
