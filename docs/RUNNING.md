# Running the experiment

`scripts/night_run.sh` runs every condition repeatedly and unattended, and writes everything a run
produces under `~/pqc/results/night_YYYYMMDD_HHMM/`. It expects the layout created by `setup/`.

## Start

```bash
cp scripts/night_run.sh ~/pqc/
# optional: DL=<folder> also copies the packed results there at the end
setsid nohup bash ~/pqc/night_run.sh > ~/pqc/night_console.log 2>&1 &
sleep 30; tail -f ~/pqc/results/night_*/progress.log     # Ctrl+C stops only the tail
```

Watch the first run finish (about 4 to 5 minutes) before leaving it: the log should show four
benchmark lines and `rep1: done in ... s (4/4 benchmarks)`.

On a laptop, disable sleep while on mains power and postpone system updates for the duration.

## Progress

```bash
cat ~/pqc/night_status.txt
```

```
progress 26% (13/50 runs) | elapsed 0h 58m | remaining ~2h 46m | expected finish 05:12 (22/10) | avg 4m 30s per run | now: running mldsa65 rep 4
```

The remaining time uses the average duration of the runs completed so far (4.5 min before the
first one). If a condition fails twice in a row it is dropped and the totals shrink accordingly.

## Stop early

```bash
touch ~/pqc/STOP_NIGHT
```

The current run finishes, then the results are packed as usual.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `HOURS` | 9.5 | no new run starts after this many hours |
| `MAX_REPS` | 10 | repetitions per condition |
| `CONDS` | `ecdsa mldsa44 mldsa65 mldsa87 hybrid44` | conditions to run |
| `DL` | empty | folder that also receives the packed results |

Example: `HOURS=2 MAX_REPS=3 CONDS="ecdsa mldsa44" bash ~/pqc/night_run.sh`

## What one run does

1. `network.sh down`, then remove any leftover chaincode containers.
2. Reset the CA configuration and `registerEnroll.sh` from git, then set the key request of the
   condition on the three CAs and on the 11 MSP enrolments (TLS enrolments keep ECDSA keys) and the
   channel capability (V3_0, or V3_0_HYBRID for `hybrid44`).
3. `network.sh up createChannel -c mychannel -ca`, then `deployCCAAS`.
4. Wait until both chaincode services log `Bootstrap process completed`, then one `AnchorAlert`
   through the peer CLI (up to 6 attempts, 10 s apart; a refused invoke writes nothing).
5. 2,000 transactions at concurrency 20 and 50, `du -sb` of the ledger (4,001 alerts), then 2,000 at
   concurrency 10 and 100, sampling `docker stats` about every 4 s (each
   `docker stats --no-stream` call takes about 2 s, followed by a 2 s sleep).
6. For the first successful run of each condition: copy the block files and decode them.

## Output

```
night_YYYYMMDD_HHMM/
  progress.log          everything the driver logged
  summary.csv           one row per benchmark: cond, rep, concurrency, n_tx, failed_workers,
                        tx_per_s, mean/p50/p95/p99 latency (ms), wall_s, client key type
  environment.txt       machine, versions, image ids
  tools/                the decoder and a copy of the driver that produced the results
  <cond>/rep<k>/
    up.log deploy.log invoke.log down.log
    certs.txt           DER/PEM sizes and algorithms of the certificates
    bench_c<C>.json     result of each benchmark
    bench_c<C>.log      client output
    stats_c<C>.csv      container CPU, memory, network, about every 4 s
    du_after_c20_c50.txt du_end.txt blockfiles_ls.txt
    decode_blockfile_00000N.json   (first successful run of the condition)
```

The packed archive `night_YYYYMMDD_HHMM.tgz` leaves out the raw block files.

# Block cutting and identity size: `scripts/blockcut_run.sh`

A second unattended driver, with the same network set-up, CA configuration and benchmark client as
`night_run.sh`. It writes everything under `~/pqc/results/blockcut_YYYYMMDD_HHMM/`.

```bash
cp scripts/blockcut_run.sh ~/pqc/
setsid nohup bash ~/pqc/blockcut_run.sh > ~/pqc/blockcut_console.log 2>&1 &
sleep 30; tail -f ~/pqc/results/blockcut_*/progress.log    # Ctrl+C stops only the tail
cat ~/pqc/blockcut_status.txt                              # progress, remaining time, expected finish
touch ~/pqc/STOP_BLOCKCUT                                  # stop after the current run
```

**Phase 1, identity size** (one run per condition, about 15 minutes): the CLI invoke and 2,000
alerts at 20 clients with the default block cutting. The peer's block files are copied out, rebuilt
by `tools/mitigation_estimate.py` with every identity stored as DER instead of PEM, or as a 32-byte
reference, and compressed with gzip, xz and (if installed) zstd. Only the JSON result is kept.

**Phase 2, block cutting**: each cell `<condition>:<setting>` is repeated `REPS` times in a new
random order per repetition, with the CLI invoke and 2,000 alerts at 20, 50 and 10 clients.

| Setting | PreferredMaxBytes | BatchTimeout |
| --- | --- | --- |
| `pmb512k_bt2s` (control, test-network default) | 512 KB | 2s |
| `pmb1m_bt2s` | 1 MB | 2s |
| `pmb512k_bt500ms` | 512 KB | 500ms |

MaxMessageCount stays 10. The setting is written to `configtx/configtx.yaml` before the network
starts, and the values in force are read back from the channel's genesis block
(`configtxgen -inspectBlock`); a run whose genesis block holds other values is discarded. The ledger
height is read with `peer channel getinfo` before and after every benchmark, and
`tools/block_sizes.py` records the transactions and bytes of every block, so each benchmark's own
blocks can be counted (if the height cannot be read, `summarize_blockcut.py` assigns blocks to the
benchmarks by transaction count). `configtx.yaml` and the CA files are restored to the defaults at
the end, also when the driver is stopped or killed; batch values left by a run killed with `kill -9`
are restored when the driver next starts.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HOURS` | 6 | no new run starts after this many hours |
| `REPS` | 10 | repetitions of every cell (0 skips phase 2) |
| `RAW_CONDS` | all five conditions | phase 1 conditions (empty skips phase 1) |
| `CELLS` | `mldsa87` and `mldsa44` with each of the three settings | phase 2 cells |
| `DL` | empty | folder that also receives the packed results |

Output, in addition to the per-run files listed above:

```
blockcut_YYYYMMDD_HHMM/
  summary.csv           phase, cond, setting, rep, concurrency, ..., height_before, height_after
  summary_tables.txt    output of tools/summarize_blockcut.py
  identity_size/<cond>/identity_size.json   PEM, DER, reference and compressed bytes per transaction
  <cond>/<setting>/rep<k>/
    genesis.json batch_in_force.txt   batch settings in the channel's genesis block
    blocks.json                       [number, envelopes, config envelopes, bytes] per block
```

Summary: `python3 -I tools/summarize_blockcut.py ~/pqc/results/blockcut_YYYYMMDD_HHMM`.

# TLS key exchange: `scripts/tls_run.sh`

For each condition the network is brought up (no chaincode), and peer0.org1 (7051), peer0.org2 (9051),
the orderer (7050) and the org1 CA (7054) are probed from a Go client (`tools/tlsprobe`, built on the
test machine with the local toolchain, i.e. the TLS stack of the Fabric nodes) and a Node.js client
(`tools/tls_probe_node.mjs`, the stack of the benchmark client and fabric-gateway), each with the
default key exchange, X25519 only and X25519MLKEM768 only, `N` full handshakes per setting. The build
information (Go version, DefaultGODEBUG) of the binaries inside the peer, orderer and CA images and the
TLS certificate sizes and algorithms are recorded. About 10 to 15 minutes.

```bash
cp scripts/tls_run.sh ~/pqc/
DL=<folder> bash ~/pqc/tls_run.sh          # CONDS=... N=50
```

`summary_tables.txt` gives, per condition, endpoint and client, the negotiated group (reported by Go
1.25 or later, or inferred from the bytes read: an X25519MLKEM768 server share is 1088 bytes larger),
the handshake bytes and median time against X25519 only, and whether X25519MLKEM768 alone is accepted.
