# Setup

Tested on Windows 11 with Ubuntu 24.04 in WSL 2 and Docker Desktop (WSL integration enabled).
Any Linux host with Docker Engine works the same way. All paths below are under `~/pqc`.

## 1. Toolchain

```bash
# Go 1.27 (the forks need crypto/mldsa)
wget https://go.dev/dl/go1.27.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.27.0.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc && export PATH=/usr/local/go/bin:$PATH
go version                       # go1.27.0

# Node.js 24 (OpenSSL 3.5 provides ML-DSA to the benchmark client)
node -v; node -p "process.versions.openssl"
```

Other tools: `git`, `make`, `jq`, `python3`, `openssl`.

## 2. Build the forks

```bash
bash setup/build_forks.sh
```

The script clones the three forks side by side (the Fabric fork uses `replace ... => ../fabric-lib-go`),
runs the MSP and CA tests, builds the binaries into `~/pqc/bin`, builds the Docker images and tags
them `:pqc`.

Two details matter:

* The Fabric Makefile derives `GO_VER` from `go.mod` as `1.27`, which is not a downloadable Go
  release, so the image build needs `GO_VER=1.27.0`.
* The image builds also tag `:latest`. If another Fabric network on the same machine uses the stock
  images through `:latest`, put them back, for example:

  ```bash
  docker tag hyperledger/fabric-peer:2.5.9    hyperledger/fabric-peer:latest
  docker tag hyperledger/fabric-orderer:2.5.9 hyperledger/fabric-orderer:latest
  docker tag hyperledger/fabric-ca:1.5.17     hyperledger/fabric-ca:latest
  ```

## 3. Prepare fabric-samples

```bash
bash setup/setup_fabric_samples.sh
```

This uses a separate checkout in `~/pqc/fabric-samples` and changes it in three ways:

| Change | Why |
| --- | --- |
| `:latest` image tags become `:pqc` in the compose files and in `network.sh` | run the fork images |
| Channel capability `V2_0` becomes `V3_0` | ML-DSA identities need MSP v3 |
| The global orderer `Addresses` are removed from `configtx.yaml` | V3_0 refuses them; each organisation keeps `OrdererEndpoints` |

**Always set `export COMPOSE_PROJECT_NAME=pqcnet` before `network.sh`.** Without it Docker Compose
names the volumes after the folder (`compose_*`). Any other fabric-samples checkout on the machine
uses the same names, so the new network would open the other network's ledgers, and
`network.sh down` would delete them. With the project name set, only `pqcnet_*` volumes are used.

## 4. Install the workload

```bash
bash setup/install_workload.sh
```

This copies `chaincode/` and `bench/` to `~/pqc/cityanchor`, installs the Fabric Gateway client and
checks that Node.js can sign with ML-DSA.

## 5. Manual smoke test (optional)

```bash
cd ~/pqc/fabric-samples/test-network
export COMPOSE_PROJECT_NAME=pqcnet PATH=~/pqc/bin:$PATH
./network.sh up createChannel -c mychannel -ca
./network.sh deployCCAAS -ccn cityanchor -ccp ~/pqc/cityanchor/chaincode
./network.sh down
```

`scripts/night_run.sh` does all of this, for every condition, by itself.
