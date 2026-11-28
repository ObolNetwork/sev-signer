#!/bin/bash
# Signing and slashing checks against a running signer, with the public test
# key from signer/tests/vectors (keystore-0, Hoodi). Used by the seal/unseal
# test in docs/hardware-runbook.md.
#
#   scripts/sign-check.sh URL CA_CERT first     # 200, signature = known vector
#   scripts/sign-check.sh URL CA_CERT conflict  # 412: same target, other root
#   scripts/sign-check.sh URL CA_CERT replay    # 200: identical request again
#                                               (live mode: only before a restart;
#                                               after one the start floor refuses it)
#
# URL is the signing listener, e.g. https://127.0.0.1:19000. Extra curl flags
# (a client certificate for mTLS) go in SIGN_CHECK_CURL_ARGS.
#
# Live mode (SIGN_CHECK_LIVE=1), for a signer with the start floor on (the
# default on Hoodi): the test vector's epoch is long past, so the signer
# refuses it. Live mode instead builds an attestation for the current Hoodi
# epoch, retries while the start floor still refuses it (up to about four
# epochs after the signer started), and compares the signature with a
# reference signer given as SIGN_CHECK_REF="URL CA_CERT". The reference is a
# local insecure-dev dvtee with the same keystore and
# --anti-rollback false. The request is kept in SIGN_CHECK_STATE (default
# ./sign-check-live.json) so that conflict and replay reuse its target.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VECTORS=$ROOT/signer/tests/vectors/signing_vectors.json
URL=${1:?URL} CA=${2:?CA certificate} MODE=${3:?first|conflict|replay}
read -r -a extra <<<"${SIGN_CHECK_CURL_ARGS:-}"

pubkey=$(jq -r .public_key "$VECTORS")
vec=$(jq -c '.vectors[] | select(.name == "attestation")' "$VECTORS")

post() { # url ca body outfile -> HTTP code
	curl -sS -o "$4" -w '%{http_code}' --cacert "$2" "${extra[@]}" \
		-H 'Content-Type: application/json' -H 'Accept: application/json' \
		--data-binary "$3" "$1/api/v1/eth2/sign/$pubkey"
}

if [[ ${SIGN_CHECK_LIVE:-} == 1 ]]; then
	state=${SIGN_CHECK_STATE:-./sign-check-live.json}
	read -r ref_url ref_ca <<<"${SIGN_CHECK_REF:?SIGN_CHECK_REF=\"URL CA_CERT\" of the reference signer}"
	if [[ $MODE == first || ! -s $state ]]; then
		# Hoodi: genesis 1742213400, 12 s slots, 32-slot epochs.
		slot=$((($(date +%s) - 1742213400) / 12))
		epoch=$((slot / 32))
		jq -c --arg slot "$slot" --arg s "$((epoch - 1))" --arg t "$epoch" --arg r "0x$(openssl rand -hex 32)" '
			.request | del(.signingRoot)
			| .attestation.slot = $slot | .attestation.beacon_block_root = $r
			| .attestation.source.epoch = $s | .attestation.target.epoch = $t' <<<"$vec" >"$state"
	fi
	body=$(<"$state")
	case $MODE in
	first | replay) want=200 ;;
	conflict) body=$(jq -c '.attestation.beacon_block_root = "0x00000000000000000000000000000000000000000000000000000000000000cc"' <<<"$body"); want=412 ;;
	*) echo "mode must be first, conflict or replay" >&2; exit 2 ;;
	esac
	out=$(mktemp)
	trap 'rm -f "$out"' EXIT
	for _ in $(seq 120); do
		code=$(post "$URL" "$CA" "$body" "$out")
		[[ $want == 200 && $code == 412 ]] && grep -q 'start floor' "$out" || break
		echo "$MODE: start floor still refuses epoch $(jq -r .attestation.target.epoch <<<"$body"); waiting"
		# A new target past the floor: rebuild for the current epoch.
		sleep 12
		tries=$((${SIGN_CHECK_TRIES:-0} + 1))
		((tries < 150)) || { echo "FAIL: still below the start floor after 30 minutes" >&2; exit 1; }
		[[ $MODE == first ]] && SIGN_CHECK_TRIES=$tries exec "$0" "$URL" "$CA" first
	done
	echo "$MODE: HTTP $code $(head -c 300 "$out")"
	[[ $code == "$want" ]] || { echo "FAIL: expected HTTP $want" >&2; exit 1; }
	if [[ $want == 200 ]]; then
		ref=$(mktemp)
		[[ $(post "$ref_url" "$ref_ca" "$body" "$ref") == 200 ]] || { echo "FAIL: reference signer: $(head -c 300 "$ref")" >&2; exit 1; }
		[[ $(jq -r .signature "$out") == "$(jq -r .signature "$ref")" ]] \
			|| { echo "FAIL: signature differs from the reference signer" >&2; exit 1; }
		rm -f "$ref"
		echo "signature matches the reference signer"
	fi
	echo PASS
	exit 0
fi

case $MODE in
first | replay) body=$(jq -c .request <<<"$vec"); want=200 ;;
conflict)
	body=$(jq -c '.request | del(.signingRoot)
		| .attestation.beacon_block_root = "0x00000000000000000000000000000000000000000000000000000000000000cc"' <<<"$vec")
	want=412 ;;
*) echo "mode must be first, conflict or replay" >&2; exit 2 ;;
esac

out=$(mktemp)
trap 'rm -f "$out"' EXIT
code=$(curl -sS -o "$out" -w '%{http_code}' --cacert "$CA" "${extra[@]}" \
	-H 'Content-Type: application/json' -H 'Accept: application/json' \
	--data-binary "$body" "$URL/api/v1/eth2/sign/$pubkey")
echo "$MODE: HTTP $code $(head -c 300 "$out")"
[[ $code == "$want" ]] || { echo "FAIL: expected HTTP $want" >&2; exit 1; }
if [[ $want == 200 ]]; then
	sig=$(jq -r .signature "$out")
	[[ $sig == "$(jq -r .signature <<<"$vec")" ]] || { echo "FAIL: signature differs from the test vector" >&2; exit 1; }
	echo "signature matches the go-eth2-client/herumi test vector"
fi
echo PASS
