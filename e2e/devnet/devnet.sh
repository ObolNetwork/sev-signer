#!/usr/bin/env bash
# Kurtosis devnet with a 3-of-4 charon DV where every operator signs through its own dvtee.
#
#   Kurtosis enclave: geth + Lighthouse BN, plus a Lighthouse VC with genesis keys 0..55
#   relay ─┬─ pod0: charon0 + dvtee0 + Lighthouse VC  (mTLS)
#          ├─ pod1: charon1 + dvtee1 + Teku VC        (mTLS)
#          ├─ pod2: charon2 + dvtee2 + Lodestar VC    (server TLS only: no client-cert option)
#          └─ pod3: charon3 + dvtee3 + Prysm VC       (server TLS only: no client-cert option)
#
# Genesis keys 56..63 are split into the cluster, so the DV attests, aggregates, proposes and signs
# sync-committee duties on a real chain. Each pod's containers share charon-i's network namespace: the
# VC reaches charon at 127.0.0.1:3600 and dvtee at https://127.0.0.1:9000, which matches the
# signer certificate's SANs (localhost, 127.0.0.1).
#
#   CHARON=/path/to/charon DVTEE=/path/to/dvtee e2e/devnet/devnet.sh [command]
#
# Commands (default: all):
#   all      up, keys, cluster, pods, wait, summary, checks, down
#   up       start the Kurtosis enclave and the relay, and fetch genesis
#   keys     derive the DV keys from the genesis mnemonic and check they are active
#   cluster  split them into a 3-of-4 charon cluster
#   pods     start charon, dvtee and the VCs
#   wait     run until SLOTS slots past the pods' start
#   summary  per-node sign counts and rejections, charon duty results, DV proposals and balances
#   checks   400 + log line on a malformed request, SIGTERM restart timing, then a slashing replay (412)
#   down     save logs to $WORKDIR/logs and remove every container and the enclave
#
# Environment:
#   CHARON, DVTEE  host binaries (dvtee built with --features insecure-dev)
#   KURTOSIS            Kurtosis CLI (default: kurtosis)
#   ETH_PKG             ethereum-package locator (default: ObolNetwork fork 6.1.0-obol.6)
#   ENCLAVE             enclave name (default: dvtee-devnet); containers are named ${ENCLAVE}-*
#   WORKDIR             state and logs (default: ./devnet-work)
#   SLOTS               slots for `wait` (default: 160, i.e. 5 epochs)
#   CHARON_DEBUG_NODES  node indices whose charon logs at debug, e.g. "1" (default: none)
#   GLOAS_EPOCH         Gloas fork epoch (default: 18446744073709551615, not scheduled). Every client
#                       image must support Gloas when it is scheduled; see README.md.
#   EL_IMAGE, CL_IMAGE  Kurtosis geth and Lighthouse BN/VC images (default: those in kurtosis-args.yaml)
#   LIGHTHOUSE, TEKU, LODESTAR, PRYSM
#                       DV validator client images (defaults below)
#   SIGNER3_REMOTE      host:port of a dvtee running elsewhere, e.g. in an SEV-SNP guest
#                       (docs/hardware-runbook.md). pod3 then gets a TCP forwarder from 127.0.0.1:9000
#                       to it instead of a local signer; TLS still ends in the remote signer.
#   SIGNER3_CERT        with SIGNER3_REMOTE: that signer's certificate (from its attestation evidence)
#   SIGNER3_LOG         with SIGNER3_REMOTE: its log (the guest's serial log), for the summary counts
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CHARON=${CHARON:?path to charon (needs --testnet-capella-hard-fork)}
DVTEE=${DVTEE:?path to dvtee built with --features insecure-dev}
CHARON=$(realpath "$CHARON")
DVTEE=$(realpath "$DVTEE")
KURTOSIS=${KURTOSIS:-kurtosis}
ETH_PKG=${ETH_PKG:-github.com/ObolNetwork/ethereum-package@6.1.0-obol.6}
ENCLAVE=${ENCLAVE:-dvtee-devnet}
W=$(mkdir -p "${WORKDIR:-$PWD/devnet-work}" && realpath "${WORKDIR:-$PWD/devnet-work}")
SLOTS=${SLOTS:-160}
CHARON_DEBUG_NODES=${CHARON_DEBUG_NODES:-}
GLOAS_EPOCH=${GLOAS_EPOCH:-18446744073709551615}
[[ $GLOAS_EPOCH =~ ^[0-9]+$ ]] || { echo "GLOAS_EPOCH must be an epoch number" >&2; exit 1; }
EL_IMAGE=${EL_IMAGE:-}
CL_IMAGE=${CL_IMAGE:-}
SIGNER3_REMOTE=${SIGNER3_REMOTE:-}
if [[ -n $SIGNER3_REMOTE ]]; then
  [[ $SIGNER3_REMOTE =~ ^[0-9A-Za-z.-]+:[0-9]+$ ]] || { echo "SIGNER3_REMOTE must be host:port" >&2; exit 1; }
  [[ -f ${SIGNER3_CERT:-} ]] || { echo "SIGNER3_REMOTE needs SIGNER3_CERT (the remote signer's cert.pem)" >&2; exit 1; }
  SIGNER3_CERT=$(realpath "$SIGNER3_CERT")
fi

P=$ENCLAVE
NET=kt-$ENCLAVE
TOOLS=dvtee-devnet-tools
LIGHTHOUSE=${LIGHTHOUSE:-sigp/lighthouse:v8.3.3}
TEKU=${TEKU:-consensys/teku:26.10.3}
LODESTAR=${LODESTAR:-chainsafe/lodestar:v1.50.1}
PRYSM=${PRYSM:-offchainlabs/prysm-validator:v7.3.1}
VALTOOLS=protolambda/eth2-val-tools:latest
DV_FIRST=56 DV_END=64 # genesis key range split into the DV (Kurtosis VC loads 0..55)
FEE=0x000000000000000000000000000000000000dEaD
U=(--user "$(id -u):$(id -g)" -e HOME=/tmp)
LOGOPT=(--log-opt max-size=200m)

log() { echo "[$(date -u +%T)] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }
env_load() { [[ -f $W/env ]] || die "run '$0 up' first"; . "$W/env"; }
bn() { docker exec "$P-relay" curl -sSf "$BN$1"; }
bn_post() { docker exec "$P-relay" curl -sSf -H 'Content-Type: application/json' -d "$2" "$BN$1"; }
head_slot() { bn /eth/v1/beacon/headers/head | jq -r .data.header.message.slot; }
cfg() { awk -v k="$1:" '$1 == k {gsub(/["\047]/, "", $2); print $2}' "$W/genesis/config.yaml"; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

# kurtosis-args.yaml with GLOAS_EPOCH and any image overrides applied.
kurtosis_args() {
  local sed_args=(-e "s/^\( *gloas_fork_epoch:\).*/\1 $GLOAS_EPOCH/")
  [[ -n $EL_IMAGE ]] && sed_args+=(-e "s|^\( *el_image:\).*|\1 $EL_IMAGE|")
  [[ -n $CL_IMAGE ]] && sed_args+=(-e "s|^\( *cl_image:\).*|\1 $CL_IMAGE|" -e "s|^\( *vc_image:\).*|\1 $CL_IMAGE|")
  sed "${sed_args[@]}" "$HERE/kurtosis-args.yaml" >"$W/kurtosis-args.yaml"
  grep -q "^ *gloas_fork_epoch: $GLOAS_EPOCH\$" "$W/kurtosis-args.yaml" || die "gloas_fork_epoch not templated"
}

up() {
  docker build -q -t "$TOOLS" "$HERE" >/dev/null
  kurtosis_args
  log "kurtosis run $ETH_PKG (enclave $ENCLAVE, gloas_fork_epoch $GLOAS_EPOCH)"
  "$KURTOSIS" run --enclave "$ENCLAVE" "$ETH_PKG" --args-file "$W/kurtosis-args.yaml" >"$W/kurtosis-run.log" 2>&1 \
    || { tail -n 30 "$W/kurtosis-run.log" | strip >&2; die "kurtosis run failed (see $W/kurtosis-run.log)"; }
  rm -rf "$W/genesis"
  "$KURTOSIS" files download "$ENCLAVE" el_cl_genesis_data "$W/genesis" >/dev/null
  local cl; cl=$(docker ps --filter "network=$NET" --format '{{.Names}}' | grep '^cl-1-' | head -1)
  [[ -n $cl ]] || die "no cl-1-* container on network $NET"
  BN=http://$cl:4000
  mkdir -p "$W/run/relay"
  docker run -d --name "$P-relay" --network "$NET" --memory 256m "${U[@]}" "${LOGOPT[@]}" \
    -v "$CHARON:/usr/local/bin/charon:ro" -v "$W/run/relay:/data" "$TOOLS" \
    charon relay --data-dir /data --http-address 0.0.0.0:3640 --p2p-tcp-address 0.0.0.0:3650 \
    --p2p-advertise-private-addresses --monitoring-address 0.0.0.0:3660 --log-color=disable >/dev/null
  local g; until g=$(bn /eth/v1/beacon/genesis 2>/dev/null); do sleep 2; done
  cat >"$W/env" <<EOF
BN=$BN
GT=$(jq -r .data.genesis_time <<<"$g")
GVR=$(jq -r .data.genesis_validators_root <<<"$g")
GFV=$(cfg GENESIS_FORK_VERSION)
CFV=$(cfg CAPELLA_FORK_VERSION)
CHAIN_ID=$(cfg DEPOSIT_CHAIN_ID)
EOF
  # dvtee takes its fork schedule from this file (--network <config.yaml>).
  local ge; ge=$(cfg GLOAS_FORK_EPOCH)
  [[ ${ge:-18446744073709551615} == "$GLOAS_EPOCH" ]] || die "genesis config.yaml has GLOAS_FORK_EPOCH $ge, want $GLOAS_EPOCH"
  cat "$W/env" >&2
}

keys() {
  env_load
  local m; m=$(sed -n 's/^ *preregistered_validator_keys_mnemonic: *"\(.*\)"$/\1/p' "$HERE/kurtosis-args.yaml")
  [[ $(wc -w <<<"$m") -ge 12 ]] || die "mnemonic not found in kurtosis-args.yaml"
  rm -rf "$W/keys" && mkdir -p "$W/keys/split"
  docker run --rm --network none "${U[@]}" -v "$W/keys:/k" "$VALTOOLS" keystores --insecure --prysm-pass x \
    --out-loc /k/raw --source-mnemonic "$m" --source-min $DV_FIRST --source-max $DV_END >/dev/null
  local i=0 p
  for d in "$W"/keys/raw/keys/0x*; do
    p=$(basename "$d")
    cp "$d/voting-keystore.json" "$W/keys/split/keystore-$i.json"
    cp "$W/keys/raw/secrets/$p" "$W/keys/split/keystore-$i.txt"
    echo "$i $p $(bn "/eth/v1/beacon/states/head/validators/$p" | jq -r '"\(.data.index) \(.data.status)"')"
    i=$((i + 1))
  done >"$W/keys/split-map.txt"
  rm -rf "$W/keys/raw"
  cat "$W/keys/split-map.txt" >&2
  [[ $(grep -c active_ongoing "$W/keys/split-map.txt") -eq $((DV_END - DV_FIRST)) ]] || die "not every DV key is active"
}

cluster() {
  env_load
  rm -rf "$W/cluster"
  docker run --rm --network none "${U[@]}" -v "$CHARON:/usr/local/bin/charon:ro" -v "$W:/w" "$TOOLS" \
    charon create cluster --nodes 4 --threshold 3 --split-existing-keys --split-keys-dir /w/keys/split \
    --testnet-name "$ENCLAVE" --testnet-chain-id "$CHAIN_ID" --testnet-fork-version "$GFV" \
    --testnet-genesis-timestamp "$GT" --withdrawal-addresses $FEE --fee-recipient-addresses $FEE \
    --cluster-dir /w/cluster >/dev/null
  log "cluster: $(jq '.distributed_validators | length' "$W/cluster/node0/cluster-lock.json") DVs, 3-of-4"
}

charon_up() {
  local i=$1 lvl=info
  [[ " $CHARON_DEBUG_NODES " == *" $i "* ]] && lvl=debug
  docker run -d --name "$P-charon$i" --network "$NET" --memory 512m "${U[@]}" "${LOGOPT[@]}" \
    -v "$CHARON:/usr/local/bin/charon:ro" -v "$W/cluster/node$i:/cluster:ro" "$TOOLS" \
    charon run --nickname "node$i" --lock-file /cluster/cluster-lock.json \
    --private-key-file /cluster/charon-enr-private-key --beacon-node-endpoints "$BN" \
    --p2p-relays "http://$P-relay:3640" --p2p-tcp-address 0.0.0.0:3610 \
    --validator-api-address 127.0.0.1:3600 --monitoring-address 0.0.0.0:3620 \
    --testnet-name "$ENCLAVE" --testnet-chain-id "$CHAIN_ID" --testnet-fork-version "$GFV" \
    --testnet-genesis-timestamp "$GT" --testnet-capella-hard-fork "$CFV" \
    --log-level "$lvl" --log-color=disable >/dev/null
}

# Client identities for the VCs that support mTLS (node0 Lighthouse, node1 Teku), pinned by SHA-256.
client_cert() {
  local i=$1 c=$W/run/node$1/client
  mkdir -p "$c"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=vc-node$i" -keyout "$c/client.key" -out "$c/client.crt" 2>/dev/null
  openssl pkcs12 -export -inkey "$c/client.key" -in "$c/client.crt" -out "$c/client.p12" -passout pass:devnet
  printf devnet >"$c/pass.txt"
  echo "vc-node$i $(openssl x509 -in "$c/client.crt" -outform der | openssl dgst -sha256 -hex | awk '{print $NF}') duties" \
    >"$c/knownClients.txt"
}

# Bearer tokens for node1 (Teku, on top of mTLS) and node3 (Prysm), sent as the password in the signer URL.
token() { # node -> token (created on first use)
  local f=$W/run/node$1/token
  mkdir -p "$W/run/node$1"
  [[ -s $f ]] || openssl rand -hex 32 >"$f"
  cat "$f"
}

# pod3 with SIGNER3_REMOTE: a plain TCP forwarder in the pod, so Prysm still dials https://127.0.0.1:9000
# and TLS terminates in the remote signer. The remote signer's certificate replaces the local one.
signer_remote_up() {
  local i=$1
  mkdir -p "$W/run/node$i/signer-data/tls"
  cp "$SIGNER3_CERT" "$W/run/node$i/signer-data/tls/cert.pem"
  docker run -d --name "$P-signer$i" --network "container:$P-charon$i" --memory 64m "${U[@]}" "${LOGOPT[@]}" "$TOOLS" \
    socat TCP-LISTEN:9000,bind=127.0.0.1,fork,reuseaddr "TCP:$SIGNER3_REMOTE" >/dev/null
}

signer_up() {
  local i=$1 mtls=()
  [[ $i == 3 && -n $SIGNER3_REMOTE ]] && { signer_remote_up "$i"; return; }
  [[ $i == 0 || $i == 1 ]] && mtls=(--tls-known-clients /node/client/knownClients.txt)
  if [[ $i == 1 || $i == 3 ]]; then
    echo "vc-node$i $(token "$i") duties" >"$W/run/node$i/tokens.txt"
    mtls+=(--auth-token-file /node/tokens.txt)
  fi
  mkdir -p "$W/run/node$i/signer-data"
  docker run -d --name "$P-signer$i" --network "container:$P-charon$i" --memory 256m "${U[@]}" "${LOGOPT[@]}" \
    -e RUST_LOG=dvtee=debug,tower_http=info \
    -v "$DVTEE:/usr/local/bin/dvtee:ro" -v "$W/cluster/node$i/validator_keys:/keys:ro" \
    -v "$W/cluster/node$i/cluster-lock.json:/cluster-lock.json:ro" \
    -v "$W/run/node$i:/node" -v "$W/genesis:/genesis:ro" "$TOOLS" \
    dvtee serve --platform insecure-dev --insecure-dev-root-key /node/dev-root.key \
    --network /genesis/config.yaml --genesis-validators-root "$GVR" \
    --keystores-dir /keys --data-dir /node/signer-data --cluster-lock /cluster-lock.json \
    --listen 127.0.0.1:9000 --public-listen 0.0.0.0:9001 "${mtls[@]}" >/dev/null
}

vc_up() {
  local i=$1 n=$W/run/node$1
  mkdir -p "$n/vc"
  case $i in
  0) # Lighthouse: web3signer definitions with the signer cert as root CA and a PKCS#12 client identity.
    mkdir -p "$n/vc/validators"
    for ks in "$W"/cluster/node0/validator_keys/keystore-*.json; do
      cat <<EOF
- enabled: true
  voting_public_key: "0x$(jq -r .pubkey "$ks")"
  type: web3signer
  url: "https://127.0.0.1:9000"
  root_certificate_path: "/node/signer-data/tls/cert.pem"
  client_identity_path: "/node/client/client.p12"
  client_identity_password: "devnet"
  request_timeout_ms: 12000
EOF
    done >"$n/vc/validators/validator_definitions.yml"
    docker run -d --name "$P-vc0" --network "container:$P-charon0" --memory 512m "${U[@]}" "${LOGOPT[@]}" \
      -v "$n:/node" -v "$W/genesis:/genesis:ro" $LIGHTHOUSE \
      lighthouse vc --testnet-dir /genesis --datadir /node/vc --beacon-nodes http://127.0.0.1:3600 \
      --suggested-fee-recipient $FEE --distributed --disable-auto-discover --init-slashing-protection \
      --builder-proposals --builder-boost-factor 0 >/dev/null
    ;;
  1) # Teku: PKCS#12 client keystore, and a PKCS#12 truststore built with the image's keytool.
    docker run --rm --network none "${U[@]}" -v "$n:/node" --entrypoint keytool $TEKU \
      -importcert -noprompt -alias dvtee -file /node/signer-data/tls/cert.pem \
      -keystore /node/client/truststore.p12 -storetype PKCS12 -storepass devnet-trust >/dev/null 2>&1
    printf devnet-trust >"$n/client/truststore-pass.txt"
    docker run -d --name "$P-vc1" --network "container:$P-charon1" --memory 1g "${U[@]}" "${LOGOPT[@]}" \
      -e JAVA_OPTS=-Xmx768m -v "$n:/node" -v "$W/genesis:/genesis:ro" $TEKU \
      validator-client --network=/genesis/config.yaml --beacon-node-api-endpoint=http://127.0.0.1:3600 \
      --data-base-path=/node/vc \
      --validators-external-signer-url="https://vc:$(token 1)@127.0.0.1:9000" \
      --validators-external-signer-public-keys=external-signer \
      --validators-external-signer-keystore=/node/client/client.p12 \
      --validators-external-signer-keystore-password-file=/node/client/pass.txt \
      --validators-external-signer-truststore=/node/client/truststore.p12 \
      --validators-external-signer-truststore-password-file=/node/client/truststore-pass.txt \
      --validators-external-signer-slashing-protection-enabled=true \
      --validators-proposer-default-fee-recipient=$FEE --Xobol-dvt-integration-enabled=true >/dev/null
    ;;
  2) # Lodestar: no client-cert option; trusts the signer cert through NODE_EXTRA_CA_CERTS.
    docker run -d --name "$P-vc2" --network "container:$P-charon2" --memory 1g "${U[@]}" "${LOGOPT[@]}" \
      -e NODE_EXTRA_CA_CERTS=/node/signer-data/tls/cert.pem -e NODE_OPTIONS=--max-old-space-size=768 \
      -v "$n:/node" -v "$W/genesis:/genesis:ro" $LODESTAR \
      validator --paramsFile=/genesis/config.yaml --dataDir=/node/vc --beaconNodes=http://127.0.0.1:3600 \
      --externalSigner.urls=https://127.0.0.1:9000 --externalSigner.fetch=true \
      --suggestedFeeRecipient=$FEE --distributed >/dev/null
    ;;
  3) # Prysm: no client-cert option; trusts the signer cert through Go's SSL_CERT_FILE.
    docker run -d --name "$P-vc3" --network "container:$P-charon3" --memory 512m "${U[@]}" "${LOGOPT[@]}" \
      -e SSL_CERT_FILE=/node/signer-data/tls/cert.pem -v "$n:/node" -v "$W/genesis:/genesis:ro" $PRYSM \
      --accept-terms-of-use --datadir=/node/vc --chain-config-file=/genesis/config.yaml \
      --enable-beacon-rest-api --beacon-rest-api-provider=http://127.0.0.1:3600 \
      --beacon-rpc-provider=127.0.0.1:3600 \
      --validators-external-signer-url="https://vc:$(token 3)@127.0.0.1:9000" \
      --validators-external-signer-public-keys="https://vc:$(token 3)@127.0.0.1:9000/api/v1/eth2/publicKeys" \
      --suggested-fee-recipient=$FEE --distributed >/dev/null
    ;;
  esac
}

pods() {
  env_load
  rm -rf "$W/run/node"{0,1,2,3}
  for i in 0 1 2 3; do charon_up $i; done
  client_cert 0
  client_cert 1
  for i in 0 1 2 3; do signer_up $i; done
  for i in 0 1 2 3; do
    timeout 60 bash -c "until [[ -s '$W/run/node$i/signer-data/tls/cert.pem' ]]; do sleep 1; done" \
      || die "signer$i did not write its TLS cert: $(docker logs "$P-signer$i" 2>&1 | tail -n 3)"
  done
  for i in 0 1 2 3; do vc_up $i; done
  echo "PODS_SLOT=$(head_slot)" >>"$W/env"
  log "pods up at slot $(head_slot)"
}

wait_slots() {
  env_load
  local end=$((PODS_SLOT + SLOTS)) s last=-1
  log "running until slot $end"
  while s=$(head_slot) && ((s < end)); do
    if ((s / 32 != last)); then last=$((s / 32)); log "slot $s: $(signer_counts | tr '\n' ' ')"; fi
    sleep 12
  done
}

signer_counts() {
  for i in 0 1 2 3; do
    local l
    if [[ $i == 3 && -n $SIGNER3_REMOTE ]]; then
      l=$(strip <"${SIGNER3_LOG:-/dev/null}")
    else
      l=$(docker logs "$P-signer$i" 2>&1 | strip)
    fi
    echo "node$i rejected=$(grep -c 'rejected sign request' <<<"$l") refused=$(grep -c 'refused to sign' <<<"$l")" \
      "$(grep -oE 'kind="?[A-Z_0-9]+' <<<"$l" | sed 's/kind="\{0,1\}//' | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')"
  done
}

duty_types() { # charon log lines on stdin -> "type=count ..." over distinct duties
  { grep -oE '"duty": "[0-9]+/[a-z_]+"' || true; } | sort -u | sed -E 's|.*/([a-z_]+)"|\1|' | sort | uniq -c \
    | awk '{printf "%s=%s ", $2, $1}'
}

summary() {
  env_load
  local head; head=$(head_slot)
  echo "== head slot $head (pods started at $PODS_SLOT)"
  echo "== dvtee: rejected (400/403), refused (412), signed by kind"
  signer_counts
  # charon's tracker metrics stay at 0 in this setup, so duty outcomes come from the logs: distinct
  # duty slots charon broadcast, and the tracker's "Duty failed" lines.
  echo "== charon duties broadcast to the BN / failed, by type (distinct duty slots)"
  local i l
  for i in 0 1 2 3; do
    l=$(docker logs "$P-charon$i" 2>&1)
    echo "node$i ok:     $(grep -E 'bcast .*Successfully submitted' <<<"$l" | duty_types)"
    echo "node$i failed: $(grep -F 'Duty failed' <<<"$l" | duty_types)"
  done
  echo "== charon logs: invalid partial signatures, expired-duty drops"
  for i in 0 1 2 3; do
    l=$(docker logs "$P-charon$i" 2>&1)
    echo "node$i invalid=$(grep -ciE 'invalid partial signature|invalid signature|invalid eth2 signed data' <<<"$l")" \
      "expired_drops=$(grep -c 'Dropping partial signatures received for expired duty' <<<"$l")"
  done
  # Every slot's canonical header, scanned inside the relay container (one exec): blocks by a DV index vs
  # charon's proposer broadcasts above. Empty slots are listed, because any of them may be a DV miss.
  echo "== chain: canonical blocks from slot $((PODS_SLOT + 1)) to $head"
  local idx; idx=$(awk '{print $3}' "$W/keys/split-map.txt" | paste -sd,)
  docker exec "$P-relay" bash -c '
    dv=0; other=0; empty=""
    for ((s = $1; s <= $2; s++)); do
      p=$(curl -sf "$3/eth/v1/beacon/headers/$s" | jq -r .data.header.message.proposer_index) || { empty+=" $s"; continue; }
      if [[ ",$4," == *",$p,"* ]]; then dv=$((dv + 1)); else other=$((other + 1)); fi
    done
    echo "DV blocks: $dv, other blocks: $other, empty slots:${empty:- none}"' _ $((PODS_SLOT + 1)) "$head" "$BN" "$idx"
  gloas_payloads "$head" "$idx"
  echo "== DV balances (gwei)"
  bn "/eth/v1/beacon/states/head/validators?id=$idx" | jq -r '.data[] | "\(.index) \(.balance) \(.status)"'
}

# After Gloas: whether each DV proposal's self-built payload was revealed. A payload counts as FULL when a
# later block's bid builds on its block_hash; the newest block is still pending. Also counts charon's
# "envelope never revealed" warnings.
gloas_payloads() {
  local head=$1 idx=$2 ge from
  ge=$(cfg GLOAS_FORK_EPOCH)
  [[ -n $ge && $ge != 18446744073709551615 ]] || return 0
  from=$((ge * 32 > PODS_SLOT ? ge * 32 : PODS_SLOT + 1))
  ((from < head)) || return 0
  echo "== Gloas: DV self-built payloads from slot $from (FULL = a later bid builds on it)"
  docker exec "$P-relay" bash -c '
    declare -A hash; parents=" "; dv=()
    for ((s = $1; s <= $2; s++)); do
      b=$(curl -sf "$3/eth/v2/beacon/blocks/$s") || continue
      read -r p h ph < <(jq -r "[.data.message.proposer_index, (.data.message.body.signed_execution_payload_bid.message | .block_hash, .parent_block_hash)] | @tsv" <<<"$b")
      parents+="$ph "
      if [[ ",$4," == *",$p,"* ]]; then hash[$s]=$h; dv+=("$s"); fi
    done
    full=0; empty=""
    for s in "${dv[@]}"; do
      if [[ $parents == *" ${hash[$s]} "* ]]; then full=$((full + 1));
      elif ((s < $2)); then empty+=" $s"; fi
    done
    echo "DV proposals: ${#dv[@]}, payload FULL: $full, EMPTY:${empty:- none}"' _ "$from" "$head" "$BN" "$idx"
  local i
  for i in 0 1 2 3; do
    echo "node$i envelope_never_revealed=$(docker logs "$P-charon$i" 2>&1 | grep -c 'execution payload envelope never revealed')"
  done
}

# Sign request helpers against signer0, from inside its pod, with node0's pinned client cert.
sign0() { # share pubkey, JSON body on stdin -> response body and "HTTP <code>"
  docker exec -i "$P-signer0" curl -s -w '\nHTTP %{http_code}' --cacert /node/signer-data/tls/cert.pem \
    --cert /node/client/client.crt --key /node/client/client.key -H 'Content-Type: application/json' \
    --data-binary @- "https://127.0.0.1:9000/api/v1/eth2/sign/$1"
}

# Latest attestation in signer0's slashing DB -> share, validator index, and the on-chain AttestationData for
# that duty (sets f, share, idx, rec, data). The record moves every epoch, so re-run this right before a replay.
replay_target() {
  local d=$W/run/node0/signer-data/slashing x dv t slot s
  f=$(for x in "$d"/*.json; do jq -e .attestation "$x" >/dev/null 2>&1 && echo "$x" && break; done)
  [[ -n $f ]] || die "signer0 has no attestation in its slashing DB yet"
  share=0x$(basename "$f" .json)
  dv=$(jq -r --arg s "$share" '.distributed_validators[] | select(.public_shares[0] == $s) | .distributed_public_key' \
    "$W/cluster/node0/cluster-lock.json")
  idx=$(bn "/eth/v1/beacon/states/head/validators/$dv" | jq -r .data.index)
  rec=$(jq -c .attestation "$f")
  t=$(jq -r .target <<<"$rec")
  slot=$(bn_post "/eth/v1/validator/duties/attester/$t" "[\"$idx\"]" | jq -r '.data[0].slot')
  data=
  for ((s = slot + 1; s <= slot + 5; s++)); do
    data=$(bn "/eth/v2/beacon/blocks/$s/attestations" 2>/dev/null \
      | jq -c --arg sl "$slot" '[.data[] | select(.data.slot == $sl)][0].data // empty') && [[ -n $data ]] && break
  done
  [[ -n $data ]] || die "no on-chain attestation for slot $slot"
  echo "validator $idx, share ${share:0:14}…, slashing record $rec, duty slot $slot"
}

att_body() {
  jq -nc --argjson f "$(bn /eth/v1/beacon/states/head/fork | jq -c .data)" --arg g "$GVR" --argjson a "$1" \
    '{type: "ATTESTATION", fork_info: {fork: $f, genesis_validators_root: $g}, attestation: $a}'
}

replay() { # identical body -> 200, different beacon_block_root (same source/target) -> 412
  replay_target
  echo "-- identical:"; att_body "$data" | sign0 "$share" || true; echo
  echo "-- different beacon_block_root:"
  att_body "$(jq -c '.beacon_block_root = "0x'"$(printf '11%.0s' {1..32})"'"' <<<"$data")" | sign0 "$share" || true; echo
  echo "slashing record after: $(jq -c .attestation "$f")"
}

checks() {
  env_load
  local f share idx rec data before after since t0 t1 t2 ev=$W/restart-events.txt evpid

  echo "== 1. malformed attestation (source.epoch > target.epoch) -> expect 400, a log line, no DB write"
  replay_target
  before=$(sha256sum <"$f")
  since=$(date -u +%FT%TZ)
  att_body "$(jq -c '.source.epoch = ((.target.epoch | tonumber) + 1 | tostring)' <<<"$data")" | sign0 "$share" || true
  echo; sleep 1
  docker logs --since "$since" "$P-signer0" 2>&1 | strip | grep 'rejected sign request' || echo "(no rejected sign request line)"
  after=$(sha256sum <"$f")
  [[ $before == "$after" ]] && echo "slashing file unchanged" || echo "SLASHING FILE CHANGED"

  echo "== 2. replay before restart"
  replay

  echo "== 3. docker restart signer0 -> expect 'shutting down', exit 0, well under Docker's 10 s"
  timeout 120 docker events --filter "container=$P-signer0" --filter event=die --filter event=start \
    --format '{{.Time}} {{.Action}} exitCode={{index .Actor.Attributes "exitCode"}}' >"$ev" &
  evpid=$!
  sleep 1
  since=$(date -u +%FT%TZ)
  t0=$(date +%s.%N); docker restart "$P-signer0" >/dev/null; t1=$(date +%s.%N)
  until docker exec "$P-signer0" curl -sf -o /dev/null --cacert /node/signer-data/tls/cert.pem \
    --cert /node/client/client.crt --key /node/client/client.key https://127.0.0.1:9000/upcheck 2>/dev/null; do
    sleep 0.5
    (($(date +%s) - ${t1%.*} < 120)) || die "signer0 not serving 120 s after restart"
  done
  t2=$(date +%s.%N)
  echo "docker restart (stop + start) took $(awk "BEGIN{printf \"%.1f\", $t1 - $t0}") s;" \
    "serving again $(awk "BEGIN{printf \"%.1f\", $t2 - $t1}") s later"
  sleep 1; kill $evpid 2>/dev/null || true
  cat "$ev"
  docker logs --since "$since" "$P-signer0" 2>&1 | strip | grep -E 'shutting down|serving|listen' | cut -c1-160 || true

  echo "== 4. replay after restart (412 comes from the persisted DB)"
  replay
}

down() {
  mkdir -p "$W/logs"
  local c
  for c in $(docker ps -a --format '{{.Names}}' | grep -E "^$P-(relay|charon[0-3]|signer[0-3]|vc[0-3])$"); do
    docker logs "$c" 2>&1 | strip >"$W/logs/${c#"$P-"}.log"
  done
  for c in $(docker ps -a --filter "network=$NET" --format '{{.Names}}' | grep -E '^(el|cl|vc)-1-'); do
    docker logs "$c" 2>&1 | strip >"$W/logs/${c%%--*}.log"
  done
  docker ps -a --format '{{.Names}}' | grep -E "^$P-" | xargs -r docker rm -f >/dev/null
  "$KURTOSIS" enclave rm -f "$ENCLAVE" >/dev/null 2>&1 || true
  log "down; logs in $W/logs (the Kurtosis engine is left running: '$KURTOSIS engine stop')"
}

all() {
  trap down EXIT
  up; keys; cluster; pods; wait_slots; summary | tee "$W/summary.txt"; checks | tee "$W/checks.txt"
}

case ${1:-all} in
all | up | keys | cluster | pods | summary | checks | down) "${1:-all}" ;;
wait) wait_slots ;;
*) die "unknown command $1" ;;
esac
