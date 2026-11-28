#!/bin/bash
# Tests for the host-side scripts the hardware runbook uses, run against a
# local signer on the insecure-dev platform (no TEE needed):
#
#   (cd signer && cargo build --locked --features insecure-dev)
#   scripts/tests/run.sh signer/target/debug/dvtee
#
# Covers launch/measure command lines (--print/--dry-run), sign-check.sh
# (first/conflict/replay, and slashing protection across a restart),
# evidence fetch + verify-evidence, and snp-report-fields.py.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=$(realpath "${1:?path to dvtee built with --features insecure-dev}")
T=$(mktemp -d)
pid=''
cleanup() { [[ -z $pid ]] || kill "$pid" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
pass=0 fail=0
check() { local d=$1; shift; if "$@"; then pass=$((pass + 1)); echo "ok   $d"; else fail=$((fail + 1)); echo "FAIL $d"; fi; }
fails() { ! "$@"; }

# Command lines.
cmd=$("$ROOT/scripts/launch-snp-guest.sh" --data "$T/d.img" --provision "$T/p.img" --print)
check "launch: kernel-hashes and policy" grep -q 'sev-snp-guest\\,id=sev0\\,cbitpos=51\\,reduced-phys-bits=1\\,policy=0x30000\\,kernel-hashes=on' <<<"$cmd"
check "launch: no -append by default" fails grep -q -- '-append' <<<"$cmd"
check "launch: data disk serial" grep -q 'serial=dvtee-data' <<<"$cmd"
check "launch: root image attached read-only" grep -q 'file=.*dvtee.raw\\,format=raw\\,readonly=on' <<<"$cmd"
check "launch: provisioning disk read-only" grep -q 'id=prov\\,file=[^ ]*\\,format=raw\\,readonly=on' <<<"$cmd"
cmd=$(SNP_VCPUS=2 "$ROOT/scripts/launch-snp-guest.sh" --data d --append x --print)
check "launch: overrides and -append" grep -q -- '-smp 2 .*-append x' <<<"$cmd"
cmd=$(SEV_SNP_MEASURE=ssm "$ROOT/scripts/expected-measurement.sh" --dry-run)
check "measure: same parameters" grep -q -- '--mode snp --vmm-type QEMU --vcpus 4 --vcpu-type EPYC-v4 --guest-features 0x1' <<<"$cmd"
check "measure: no --append by default" fails grep -q -- '--append' <<<"$cmd"

# A local signer with the test vector key on Hoodi.
D=$T/data
mkdir -p "$D/keys"
cp "$ROOT"/signer/tests/vectors/keystores/keystore-0.* "$D/keys/"
start_signer() {
	"$BIN" serve --platform insecure-dev --insecure-dev-root-key "$T/root.key" --network hoodi --anti-rollback false \
		--keystores-dir "$D/keys" --data-dir "$D" --listen 127.0.0.1:29000 --public-listen 127.0.0.1:29001 \
		>>"$T/signer.log" 2>&1 &
	pid=$!
	for _ in $(seq 60); do curl -sk https://127.0.0.1:29001/upcheck >/dev/null 2>&1 && return 0; sleep 0.5; done
	return 1
}
stop_signer() { kill "$pid"; wait "$pid" 2>/dev/null; pid=''; }

check "signer starts" start_signer
CA=$D/tls/cert.pem
check "sign-check first" "$ROOT/scripts/sign-check.sh" https://127.0.0.1:29000 "$CA" first
check "sign-check conflict" "$ROOT/scripts/sign-check.sh" https://127.0.0.1:29000 "$CA" conflict
check "sign-check replay" "$ROOT/scripts/sign-check.sh" https://127.0.0.1:29000 "$CA" replay
stop_signer
check "signer restarts" start_signer
check "sign-check conflict after restart" "$ROOT/scripts/sign-check.sh" https://127.0.0.1:29000 "$CA" conflict

# Evidence: trust on first use, verify the binding, then pin the bound cert.
NONCE=$(openssl rand -hex 32)
curl -sk "https://127.0.0.1:29001/api/v1/tee/attestation?nonce=$NONCE" >"$T/evidence.json"
check "verify-evidence (insecure-dev)" "$BIN" verify-evidence --evidence "$T/evidence.json" --nonce "$NONCE" --allow-insecure-dev
jq -r .tls_certificate "$T/evidence.json" >"$T/bound.pem"
check "bound cert pins the listener" curl -sf --cacert "$T/bound.pem" https://127.0.0.1:29001/upcheck -o /dev/null
check "wrong nonce fails" fails "$BIN" verify-evidence --evidence "$T/evidence.json" --nonce "$(openssl rand -hex 32)" --allow-insecure-dev
out=$("$ROOT/scripts/snp-report-fields.py" "$T/evidence.json")
check "report fields: policy" grep -q '^policy: *0x00000000000a0000' <<<"$out"
check "report fields: debug bit" grep -q '^policy_debug: *True' <<<"$out"
m=$(jq -r .report "$T/evidence.json" | sed 's/^0x//' | cut -c $((0x90 * 2 + 1))-$((0xC0 * 2)))
check "report fields: measurement offset" grep -q "^measurement: *$m\$" <<<"$out"
check "report fields: committed TCB" test "$("$ROOT/scripts/snp-report-fields.py" --committed-tcb "$T/evidence.json")" = 0x0000000000000000
check "report fields: min TCB" test "$("$ROOT/scripts/snp-report-fields.py" --min-tcb "$T/evidence.json")" = 0x0000000000000000
stop_signer

echo
echo "$pass passed, $fail failed"
((fail == 0))
