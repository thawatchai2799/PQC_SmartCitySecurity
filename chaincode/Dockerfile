# Chaincode-as-a-Service image for CityAnchor.
# Used by:  ./network.sh deployCCAAS -ccn cityanchor -ccp ~/cityanchor/chaincode
# The peer does NOT build this image; docker build runs on your own daemon, which avoids the
# legacy /build endpoint that recent Docker Engine releases no longer expose to the peer.
FROM node:20-alpine

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

ENV CORE_CHAINCODE_ID_NAME=""
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
EXPOSE 9999

CMD ["npm", "run", "docker:start"]
