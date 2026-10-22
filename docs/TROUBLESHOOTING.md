# Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `configtxgen`: "global orderer endpoints exist, but can not be used with V3_0 capability" | `Orderer: Addresses` in `configtx.yaml` | `setup/setup_fabric_samples.sh` removes it |
| Orderer exits: "'localconfig.TopLevel' has invalid keys: Kafka" | an `orderer.yaml` from Fabric 2.x reused through a Docker volume of an older network with the same compose project name | `export COMPOSE_PROJECT_NAME=pqcnet`, remove the stale containers (not the volumes) |
| New peers open an old ledger | same compose project name as another network (`compose_*` volumes) | as above; never run `network.sh down` without `COMPOSE_PROJECT_NAME=pqcnet` |
| `deployCCAAS`: "Failed to start the container" | chaincode containers of the previous network still running (`network.sh down` quotes the container list, so its kill fails when there are two) | `docker rm -f peer0org1_cityanchor_ccaas peer0org2_cityanchor_ccaas` (the driver does this) |
| invoke: "connect: connection refused" to the chaincode | invoke sent before the chaincode server is listening | wait for `Bootstrap process completed` in both chaincode logs (the driver does this) |
| Client signatures rejected with ML-DSA identities | the fork signs the whole message with ML-DSA, not a SHA-256 digest | gateway option `hash: hash.none` and `crypto.sign(null, message, key)`, as in `bench/bench_night.mjs` |
| `crypto.generateKeyPairSync('ml-dsa-44')` fails | Node.js built against OpenSSL older than 3.5 | Node.js 24 or later |
| Image build fails downloading Go "1.27" | `GO_VER` derived from `go.mod` | `make ... GO_VER=1.27.0` |
