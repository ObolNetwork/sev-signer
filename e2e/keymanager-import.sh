#!/bin/bash
#
#   BIN=signer/target/debug/dvtee CHARON=../charon/charon e2e/keymanager-import.sh
# Keymanager import end to end on one machine: four insecure-dev dvtee signers
# in import mode, charon v1.11.3 `create cluster --keymanager-addresses`
# pushing each node's shares to its signer (charon's own HTTP client, trusting
# the signers through SSL_CERT_FILE), then the lock upload, exit 75, and a
# restart into signing mode.
set -euo pipefail

BIN=${BIN:?path to dvtee built with --features insecure-dev}
CHARON=${CHARON:?path to a charon binary (v1.11+), e.g. go build in a charon checkout}
W=${WORK_DIR:-$(mktemp -d)}; mkdir -p "$W"
head -c 32 /dev/urandom >"$W/root.key"
FEE=0x000000000000000000000000000000000000dEaD
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

start() { # i mode-args...
	local i=$1; shift
	"$BIN" serve --platform insecure-dev --insecure-dev-root-key "$W/root.key" --network hoodi \
		--anti-rollback false --data-dir "$W/s$i" --keystores-dir "$W/s$i/validator_keys" \
		--listen 127.0.0.1:$((19810 + i)) --public-listen 127.0.0.1:$((19820 + i)) \
		--auth-token-file "$W/tokens$i.txt" "$@" >>"$W/s$i.log" 2>&1 &
	PIDS+=($!)
	echo $!
}

addrs=() toks=()
for i in 0 1 2 3; do
	t=$(openssl rand -hex 32)
	echo "charon $t import" >"$W/tokens$i.txt"
	echo "vc $(openssl rand -hex 32) duties" >>"$W/tokens$i.txt"
	mkdir -p "$W/s$i"
	start $i --keymanager-import >/dev/null
	addrs+=("https://127.0.0.1:$((19820 + i))"); toks+=("$t")
done
for i in 0 1 2 3; do
	for _ in $(seq 50); do [[ -s $W/s$i/tls/cert.pem ]] && curl -sk -o /dev/null "https://127.0.0.1:$((19820 + i))/upcheck" && break; sleep 0.2; done
done
grep -h "import mode" "$W"/s*.log | head -1 | cut -c1-160

# What charon trusts: the system CAs plus each signer's certificate.
cat /etc/ssl/certs/ca-certificates.crt "$W"/s{0,1,2,3}/tls/cert.pem >"$W/bundle.pem"

echo "== charon create cluster --keymanager-addresses"
SSL_CERT_FILE=$W/bundle.pem "$CHARON" create cluster --nodes 4 --num-validators 2 --network hoodi \
	--fee-recipient-addresses $FEE --withdrawal-addresses $FEE --cluster-dir "$W/cluster" \
	--keymanager-addresses "$(IFS=,; echo "${addrs[*]}")" \
	--keymanager-auth-tokens "$(IFS=,; echo "${toks[*]}")" 2>&1 | grep -i -E "error|keymanager|import|created" | tail -5 || true
for i in 0 1 2 3; do
	echo "node$i: keys on charon's side: $(ls "$W/cluster/node$i/validator_keys" 2>/dev/null | wc -l)  in signer: $(ls "$W/s$i/validator_keys" | grep -c json)  pending: $([[ -e $W/s$i/import-pending ]] && echo yes || echo no)"
done

echo "== lock upload"
for i in 0 1 2 3; do
	code=$(curl -s -o "$W/lock$i.out" -w %{http_code} --cacert "$W/s$i/tls/cert.pem" -H "Authorization: Bearer ${toks[$i]}" \
		-H content-type:application/json --data-binary @"$W/cluster/node$i/cluster-lock.json" "${addrs[$i]}/dvtee/v1/cluster-lock")
	echo "node$i: $code $(cat "$W/lock$i.out")"
done
sleep 2
for i in 0 1 2 3; do
	pid=${PIDS[$i]}; wait "$pid" && rc=0 || rc=$?
	echo "node$i: exit $rc"
done
PIDS=()

echo "== restart in signing mode"
for i in 0 1 2 3; do start $i --keymanager-import >/dev/null; done
sleep 3
for i in 0 1 2 3; do
	grep -h -E "pinned to cluster lock|dvtee serving|import mode" "$W/s$i.log" | tail -2 | sed "s/^/node$i: /" | cut -c1-200
done
echo "== a second import is refused"
curl -s -o /dev/null -w "node0 keystores again: %{http_code}\n" --cacert "$W/s0/tls/cert.pem" -H "Authorization: Bearer ${toks[0]}" \
	-H content-type:application/json -d '{"keystores":["{}"],"passwords":["x"]}' "${addrs[0]}/eth/v1/keystores"
