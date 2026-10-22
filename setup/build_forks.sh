#!/usr/bin/env bash
# build_forks.sh - clone and build the post-quantum forks of Fabric, fabric-lib-go and Fabric CA,
# build their Docker images and tag them :pqc so that they never replace the stock :latest images.
# Requires Go 1.27 (crypto/mldsa), Docker, git and make. Everything goes under $PQC (default ~/pqc).
set -euo pipefail
PQC=${PQC:-$HOME/pqc}
mkdir -p "$PQC/bin"
cd "$PQC"

[ -d fabric ]        || git clone https://github.com/ufrn-itau-crypto-quantum/fabric.git
[ -d fabric-lib-go ] || git clone -b composite-mldsa https://github.com/ufrn-itau-crypto-quantum/fabric-lib-go.git
[ -d fabric-ca ]     || git clone -b certificate-chain https://github.com/ufrn-itau-crypto-quantum/fabric-ca.git

go version | grep -q "go1.27" || { echo "Go 1.27 is required (crypto/mldsa)"; exit 1; }

echo "== Fabric: MSP tests, binaries, images"
cd "$PQC/fabric"
git log --oneline -1
go test ./msp/ -count=1
go build -o "$PQC/bin/" ./cmd/peer ./cmd/orderer ./cmd/configtxgen ./cmd/osnadmin ./cmd/cryptogen ./cmd/configtxlator
# The Makefile reads GO_VER from go.mod as "1.27", which is not a downloadable release: pass it explicitly
make peer-docker orderer-docker GO_VER=1.27.0

echo "== Fabric CA: tests, binaries, image"
cd "$PQC/fabric-ca"
git log --oneline -1
go test ./util/ ./lib/ -run 'MLDSA|Hybrid|Composite|Intermediate' -count=1
make fabric-ca-client fabric-ca-server
make docker GO_VER=1.27.0
cp bin/fabric-ca-client bin/fabric-ca-server "$PQC/bin/"

echo "== Tag the fork images :pqc"
FABRIC_VER=$(sed -n 's/^FABRIC_VER ?= //p' "$PQC/fabric/Makefile")
CA_VER=$(sed -n 's/^BASE_VERSION ?= v//p' "$PQC/fabric-ca/Makefile")
docker tag "hyperledger/fabric-peer:$FABRIC_VER"    hyperledger/fabric-peer:pqc
docker tag "hyperledger/fabric-orderer:$FABRIC_VER" hyperledger/fabric-orderer:pqc
docker tag "hyperledger/fabric-ca:$CA_VER"          hyperledger/fabric-ca:pqc
docker images | grep -E "fabric-(peer|orderer|ca) +pqc"
echo "The fork builds also tag :latest. If another Fabric network on this machine relies on :latest,"
echo "re-tag the stock images back to :latest (see docs/SETUP.md)."
