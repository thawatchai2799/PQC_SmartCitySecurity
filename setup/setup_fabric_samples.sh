#!/usr/bin/env bash
# setup_fabric_samples.sh - prepare a separate fabric-samples checkout for the post-quantum forks.
#  * uses the fork binaries in $PQC/bin and the fork sample configuration
#  * makes the test network use the :pqc images
#  * enables channel capability V3_0 (MSP v3, required for ML-DSA identities)
#  * removes the global orderer Addresses, which V3_0 forbids (each org keeps OrdererEndpoints)
# Safe to run more than once.
set -euo pipefail
PQC=${PQC:-$HOME/pqc}
cd "$PQC"
[ -d fabric-samples ] || git clone https://github.com/hyperledger/fabric-samples.git
cd fabric-samples
[ -e bin ] || ln -s "$PQC/bin" bin
mkdir -p config
cp "$PQC/fabric/sampleconfig/core.yaml" "$PQC/fabric/sampleconfig/orderer.yaml" "$PQC/fabric/sampleconfig/configtx.yaml" config/

cd test-network
# image tags in the compose files and in network.sh's version check
grep -rlE "fabric-(peer|orderer|ca):latest" . | xargs -r sed -i -E 's/(fabric-(peer|orderer|ca)):latest/\1:pqc/g' || true
# channel capability V2_0 -> V3_0, in the Channel section only
sed -i '/Channel: &ChannelCapabilities/,/Orderer: &OrdererCapabilities/ s/V2_0: true/V3_0: true/' configtx/configtx.yaml
# remove "Addresses:" and its one entry under the Orderer defaults
sed -i '/^  Addresses:$/{N;d}' configtx/configtx.yaml

echo "== check"
grep -n -A12 "Channel: &ChannelCapabilities" configtx/configtx.yaml | grep -E "V3_0|V2_0"
grep -n "^  Addresses:" configtx/configtx.yaml && { echo "global Addresses still present"; exit 1; } || echo "global Addresses removed"
grep -rhoE "fabric-(peer|orderer|ca):[a-z0-9.]+" compose network.sh | sort | uniq -c
echo "Always run this network with: export COMPOSE_PROJECT_NAME=pqcnet"
