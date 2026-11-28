#!/usr/bin/env bash
# Local DV simnet with dvtee as one operator's remote signer.
#
#   relay ─┬─ charon node0 ── Lighthouse VC ── dvtee (insecure-dev, TLS + mTLS)
#          ├─ charon node1 (simnet validator mock)
#          ├─ charon node2 (simnet validator mock)
#          └─ charon node3 (simnet validator mock, stopped after STOP_AFTER slots)
#
# All charons use charon's simnet beacon mock, which serves Hoodi's genesis
# and fork schedule, with real 12s slots so the VC's clock agrees. The
# cluster is 3-of-4, so once node3 stops every duty needs node0's share,
# i.e. a signature produced by dvtee.
#
# This is NOT a real chain: the beacon mock accepts whatever it is given.
# It tests VC <-> dvtee compatibility, TLS/mTLS, slashing protection
# and charon's partial-signature checks on dvtee's output.
#
# Native processes, no Docker. About 250 MB of RAM in total (measured with Lighthouse).
#
# Requirements: charon (built from source is fine), lighthouse, openssl,
# curl, jq, and dvtee built with `--features insecure-dev`.
#
#   CHARON=... LIGHTHOUSE=... DVTEE=... e2e/simnet.sh [workdir]
set -euo pipefail

CHARON=${CHARON:?path to charon}
LIGHTHOUSE=${LIGHTHOUSE:-} # unset: no VC on node0 (harness smoke test only)
DVTEE=${DVTEE:?path to dvtee built with --features insecure-dev}
VALIDATORS=${VALIDATORS:-4}
SLOTS=${SLOTS:-64}            # total slots to run (2 epochs; each validator attests once per epoch)
STOP_AFTER=${STOP_AFTER:-16}  # slots before node3 is stopped
RESTART_SIGNER_AT=${RESTART_SIGNER_AT:-40} # slot at which dvtee restarts
W=${1:-$(mktemp -d)}
mkdir -p "$W/logs"
echo "workdir: $W"

pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Cluster: 4 nodes, threshold 3.
if [[ ! -d $W/cluster ]]; then
  "$CHARON" create cluster --nodes 4 --threshold 3 --network hoodi --num-validators "$VALIDATORS" \
    --insecure-keys --cluster-dir "$W/cluster" \
    --withdrawal-addresses 0x000000000000000000000000000000000000dEaD \
    --fee-recipient-addresses 0x000000000000000000000000000000000000dEaD >/dev/null
fi

# Client identity for mTLS (Lighthouse takes PKCS#12).
if [[ ! -f $W/client.p12 ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj /CN=lighthouse-vc -keyout "$W/client.key" -out "$W/client.crt" 2>/dev/null
  openssl pkcs12 -export -inkey "$W/client.key" -in "$W/client.crt" \
    -out "$W/client.p12" -passout pass:e2e
  fp=$(openssl x509 -in "$W/client.crt" -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')
  echo "lighthouse-vc $fp" >"$W/knownClients.txt"
fi

# The beacon mock's slots are not Hoodi's real ones, so the start floor (on by
# default for hoodi) would refuse every duty; insecure-dev builds may turn it off.
start_signer() {
  RUST_LOG=${SIGNER_LOG:-dvtee=debug,tower_http=info} "$DVTEE" serve \
    --platform insecure-dev --insecure-dev-root-key "$W/dev-root.key" \
    --network hoodi --anti-rollback false --keystores-dir "$W/cluster/node0/validator_keys" \
    --data-dir "$W/signer-data" --listen 127.0.0.1:9000 \
    --tls-known-clients "$W/knownClients.txt" --public-listen 127.0.0.1:9001 \
    >>"$W/logs/dvtee.log" 2>&1 &
  signer_pid=$!
  pids+=("$signer_pid")
  for _ in $(seq 50); do
    [[ -f $W/signer-data/tls/cert.pem ]] && curl -s --cacert "$W/signer-data/tls/cert.pem" \
      https://127.0.0.1:9001/upcheck >/dev/null 2>&1 && return
    sleep 0.2
  done
  echo "dvtee did not start"; tail -20 "$W/logs/dvtee.log"; exit 1
}

"$CHARON" relay --data-dir "$W/relay" --http-address 127.0.0.1:3640 \
  --p2p-tcp-address 127.0.0.1:3650 --p2p-advertise-private-addresses \
  --monitoring-address 127.0.0.1:3660 >"$W/logs/relay.log" 2>&1 &
pids+=($!)
sleep 1

start_signer

charon_pids=()
for i in 0 1 2 3; do
  mock=()
  [[ $i != 0 ]] && mock=(--simnet-validator-mock --simnet-validator-keys-dir "$W/cluster/node$i/validator_keys")
  "$CHARON" run --nickname "node$i" \
    --lock-file "$W/cluster/node$i/cluster-lock.json" \
    --private-key-file "$W/cluster/node$i/charon-enr-private-key" \
    --p2p-relays http://127.0.0.1:3640 --p2p-tcp-address "127.0.0.1:37$i$i" \
    --validator-api-address "127.0.0.1:36$i$i" --monitoring-address "127.0.0.1:38$i$i" \
    --simnet-beacon-mock --simnet-slot-duration 12s "${mock[@]}" \
    >"$W/logs/charon$i.log" 2>&1 &
  charon_pids+=($!)
  pids+=($!)
done

# Lighthouse VC on node0, signing through dvtee.
mkdir -p "$W/lh/validators"
: >"$W/lh/validators/validator_definitions.yml"
for ks in "$W"/cluster/node0/validator_keys/keystore-*.json; do
  cat >>"$W/lh/validators/validator_definitions.yml" <<EOF
- enabled: true
  voting_public_key: "0x$(jq -r .pubkey "$ks")"
  type: web3signer
  url: "https://127.0.0.1:9000"
  root_certificate_path: "$W/signer-data/tls/cert.pem"
  client_identity_path: "$W/client.p12"
  client_identity_password: "e2e"
  request_timeout_ms: 12000
EOF
done
if [[ -z $LIGHTHOUSE ]]; then
  echo "LIGHTHOUSE unset: node0 runs without a VC, so duties fail once node3 stops"
else
"$LIGHTHOUSE" vc --network hoodi --datadir "$W/lh" \
  --beacon-nodes http://127.0.0.1:3600 \
  --suggested-fee-recipient 0x000000000000000000000000000000000000dEaD \
  --init-slashing-protection --distributed \
  >"$W/logs/lighthouse.log" 2>&1 &
pids+=($!)
fi

for slot in $(seq 1 "$SLOTS"); do
  sleep 12
  if [[ $slot == "$STOP_AFTER" ]]; then
    echo "slot $slot: stopping node3; duties now need node0's dvtee share"
    kill "${charon_pids[3]}"
  fi
  if [[ $slot == "$RESTART_SIGNER_AT" ]]; then
    echo "slot $slot: restarting dvtee (slashing DB must persist)"
    kill "$signer_pid"; wait "$signer_pid" 2>/dev/null || true
    start_signer
  fi
  signed=$(grep -c ': signed' "$W/logs/dvtee.log" || true)
  refused=$(grep -c 'refused to sign' "$W/logs/dvtee.log" || true)
  ok=$(curl -s http://127.0.0.1:3800/metrics | awk '/^core_tracker_success_duties_total/ {s+=$NF} END {print s+0}')
  bad=$(curl -s http://127.0.0.1:3800/metrics | awk '/^core_tracker_failed_duties_total/ {s+=$NF} END {print s+0}')
  echo "slot $slot: dvtee signed=$signed refused=$refused | node0 duties ok=$ok failed=$bad"
done

echo
echo "== evidence"
nonce=$(openssl rand -hex 32)
curl -s --cacert "$W/signer-data/tls/cert.pem" \
  "https://127.0.0.1:9001/api/v1/tee/attestation?nonce=$nonce" >"$W/evidence.json"
"$DVTEE" verify-evidence --evidence "$W/evidence.json" --nonce "$nonce" --allow-insecure-dev | grep -E 'binding|platform'

echo
echo "== dvtee request kinds"
grep -o 'kind="\?[A-Z_]*' "$W/logs/dvtee.log" | sort | uniq -c || true
echo
echo "== charon node0 duty results (prometheus)"
curl -s http://127.0.0.1:3800/metrics | grep -E '^core_tracker_(success|failed)_duties_total' | grep -v ' 0$' | sed -E 's/\{.*duty="([a-z_]+)".*\}/ \1/' || true
echo
echo "logs in $W/logs"
