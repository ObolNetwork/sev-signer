# Runtime image for charon, dvtee and the relay in e2e/devnet. The binaries are bind-mounted from
# the host (CHARON, DVTEE), so this only carries the tools devnet.sh runs inside the enclave network
# (socat forwards pod3 to a remote signer when SIGNER3_REMOTE is set).
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl jq openssl procps socat \
 && rm -rf /var/lib/apt/lists/*
