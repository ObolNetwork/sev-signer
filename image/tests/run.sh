#!/bin/bash
# Unit tests for the guest's boot scripts, with stub cryptsetup, mkfs and
# dvtee. Needs only bash, GNU tar and coreutils:
#
#   image/tests/run.sh
#
# unlock:    the decision table (blank / LUKS / neither), fail-closed paths.
# provision: archive validation and the first-boot copy.
# start:     the flags built from provisioned settings, and a clean environment.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
UNLOCK=$REPO/image/mkosi.initrd.conf/mkosi.extra/usr/lib/dvtee/unlock
PROVISION=$REPO/image/mkosi.extra/usr/lib/dvtee/provision
START=$REPO/image/mkosi.extra/usr/lib/dvtee/start
MKDISK=$REPO/scripts/make-provision-disk.sh

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
check() { # description, then a command that must succeed
	local d=$1; shift
	if "$@"; then ok "$d"; else bad "$d"; fi
}
fails() { ! "$@"; }
not_logged() { ! grep -q -- "$1" "$STATE/log"; }

# --- stubs -------------------------------------------------------------------

STUBS=$T/stubs
mkdir -p "$STUBS"
cat >"$STUBS/cryptsetup" <<'EOF'
#!/bin/bash
# State lives in $STATE: luks (header present), key (format key), label,
# status (what `status` prints), open (mapped). Every call is logged.
echo "cryptsetup $*" >>"$STATE/log"
keyfile() { local a; while (($#)); do [[ $1 == --key-file ]] && { echo "$2"; return; }; shift; done; }
case $1 in
isLuks) [[ -e $STATE/luks ]] ;;
luksFormat)
	k=$(keyfile "$@")
	[[ $(stat -c %s "$k") == 32 ]] || exit 1
	cp "$k" "$STATE/key"; touch "$STATE/luks"
	while (($#)); do [[ $1 == --label ]] && echo "$2" >"$STATE/label"; shift; done ;;
open)
	k=$(keyfile "$@")
	cmp -s "$k" "$STATE/key" || exit 2
	touch "$STATE/open" ;;
status) cat "$STATE/status" 2>/dev/null || printf '  type:    LUKS2\n  cipher:  aegis128-random\n  keysize: 128 bits\n  integrity: aead\n' ;;
luksDump) printf 'LUKS header information\nVersion:       \t2\nLabel:         \t%s\n' "$(cat "$STATE/label")" ;;
config) [[ $2 == --label ]] && echo "$3" >"$STATE/label" ;;
close) rm -f "$STATE/open" ;;
*) exit 9 ;;
esac
EOF
cat >"$STUBS/mkfs.ext4" <<'EOF'
#!/bin/bash
echo "mkfs.ext4 $*" >>"$STATE/log"
EOF
cat >"$STUBS/dvtee" <<'EOF'
#!/bin/bash
# sealing-key: prints $STATE/sealkey, or fails if it is missing.
# serve: records its arguments and environment.
case $1 in
sealing-key)
	echo "dvtee $*" >>"$STATE/log"
	[[ -e $STATE/sealkey ]] || { echo "SNP derived key: firmware status 0x16" >&2; exit 1; }
	cat "$STATE/sealkey" ;;
serve)
	printf '%s\n' "$@" >"$STATE/serve-args"
	env >"$STATE/serve-env" ;;
esac
EOF
chmod +x "$STUBS"/*

# --- unlock ------------------------------------------------------------------

# Fresh state: a sparse zeroed "disk", a 32-byte sealing key, the minimum TCB.
unlock_env() {
	STATE=$T/u-$1
	rm -rf "$STATE" && mkdir -p "$STATE/run" "$STATE/mapper"
	truncate -s 32M "$STATE/disk"
	head -c 32 /dev/urandom >"$STATE/sealkey"
	echo 0x0000000000000000 >"$STATE/tcb"
	touch "$STATE/sev-guest" "$STATE/log"
	export STATE
}
run_unlock() {
	PATH=$STUBS:$PATH \
		DVTEE_DATA_DEV=$STATE/disk DVTEE_MIN_TCB_FILE=$STATE/tcb \
		DVTEE_RUN_DIR=$STATE/run DVTEE_BIN=$STUBS/dvtee \
		SEV_GUEST_DEV=$STATE/sev-guest DVTEE_WAIT_SECS=1 DVTEE_MAPPER_DIR=$STATE/mapper \
		"$UNLOCK" >"$STATE/out" 2>&1
}
logged() { grep -q -- "$1" "$STATE/log"; }
no_key_left() { [[ ! -e $STATE/run/data.key ]]; }

unlock_env blank
check "unlock: blank disk is formatted" run_unlock
check "unlock: AEAD parameters" logged 'luksFormat --batch-mode --type luks2 --cipher aegis128-random --key-size 128 --integrity aead'
check "unlock: cheap PBKDF for a random key" logged '--pbkdf pbkdf2 --pbkdf-force-iterations 1000'
check "unlock: min TCB passed to sealing-key" logged 'sealing-key --purpose data-disk --snp-min-tcb 0x0000000000000000 --snp-vmpl 0'
check "unlock: filesystem created" logged "mkfs.ext4 -q -F -L dvtee -m 0 $STATE/mapper/dvtee-data"
check "unlock: label marks setup done" grep -qx dvtee-data "$STATE/label"
check "unlock: key file removed" no_key_left

# Second boot on the same disk: open only.
: >"$STATE/log"
check "unlock: existing disk opens" run_unlock
check "unlock: existing disk is not reformatted" not_logged luksFormat
check "unlock: existing disk keeps its filesystem" not_logged mkfs

# A different measurement/policy/chip means a different key.
head -c 32 /dev/urandom >"$STATE/sealkey"
: >"$STATE/log"
check "unlock: wrong key fails" fails run_unlock
check "unlock: wrong key never reformats" not_logged luksFormat
check "unlock: wrong key never runs mkfs" not_logged mkfs
check "unlock: key file removed after failure" no_key_left

unlock_env sealfail
rm "$STATE/sealkey"
check "unlock: sealing-key failure fails" fails run_unlock
check "unlock: no luksFormat without a key" not_logged luksFormat
check "unlock: no open without a key" not_logged 'cryptsetup open'

unlock_env shortkey
head -c 31 /dev/urandom >"$STATE/sealkey"
check "unlock: short key fails" fails run_unlock
check "unlock: short key never formats" not_logged luksFormat

unlock_env notblank
printf 'something' | dd of="$STATE/disk" bs=1 seek=4096 conv=notrunc status=none
check "unlock: non-blank disk without LUKS is refused" fails run_unlock
check "unlock: non-blank disk is not formatted" not_logged luksFormat

unlock_env nodisk
rm "$STATE/disk"
check "unlock: missing data disk fails" fails run_unlock

unlock_env nosev
rm "$STATE/sev-guest"
check "unlock: missing /dev/sev-guest fails" fails run_unlock

unlock_env badtcb
echo 0x1234 >"$STATE/tcb"
check "unlock: malformed minimum TCB fails" fails run_unlock
check "unlock: malformed minimum TCB never calls sealing-key" not_logged sealing-key

unlock_env weak
run_unlock
printf '  type:    LUKS2\n  cipher:  aes-xts-plain64\n  keysize: 512 bits\n' >"$STATE/status"
: >"$STATE/log"
check "unlock: a header rewritten to a non-AEAD cipher is refused" fails run_unlock
check "unlock: the weak mapping is closed" logged 'cryptsetup close dvtee-data'

unlock_env interrupted
run_unlock
echo dvtee-init >"$STATE/label"
: >"$STATE/log"
check "unlock: interrupted first boot is finished" run_unlock
check "unlock: ... with mkfs" logged mkfs.ext4
check "unlock: ... and no reformat" not_logged luksFormat

# --- provision ---------------------------------------------------------------

KEYS=$T/keys
mkdir -p "$KEYS"
cp "$REPO/signer/tests/vectors/keystores/keystore-0.json" "$REPO/signer/tests/vectors/keystores/keystore-0.txt" "$KEYS/"
printf 'PRESET_BASE: mainnet\nCONFIG_NAME: testnet\n' >"$T/config.yaml"
GVR=0x$(printf '%064x' 42)

prov_env() {
	PSTATE=$T/p-$1
	rm -rf "$PSTATE" && mkdir -p "$PSTATE/data" "$PSTATE/run"
}
run_provision() {
	DVTEE_DATA=$PSTATE/data DVTEE_PROV_DEV=$1 DVTEE_RUN_DIR=$PSTATE/run DVTEE_WAIT_SECS=1 \
		"$PROVISION" >"$PSTATE/out" 2>&1
}
# A hand-made archive from a directory: tar_of DIR OUT [extra tar args]
tar_of() { local d=$1 o=$2; shift 2; tar --create --format=gnu --directory "$d" --file "$o" "$@"; }

prov_env devnet
check "make-provision-disk: devnet disk" "$MKDISK" -o "$PSTATE/prov.img" -k "$KEYS" -c "$T/config.yaml" -g "$GVR" -s localhost,127.0.0.1 -l debug
check "provision: devnet disk accepted" run_provision "$PSTATE/prov.img"
check "provision: marker written" test -f "$PSTATE/data/provisioned"
check "provision: keys copied 0600" test "$(stat -c %a "$PSTATE/data/validator_keys/keystore-0.json")" = 600
check "provision: config copied" cmp -s "$T/config.yaml" "$PSTATE/data/config/config.yaml"
check "provision: second run refused" fails run_provision "$PSTATE/prov.img"

# start: flags from the provisioned settings, environment cleared. start runs
# the signer under `env -i`, so the stub has its output path baked in.
serve_stub() {
	printf '#!/bin/bash\nprintf "%%s\\n" "$@" >%q\nenv >%q\n' "$PSTATE/serve-args" "$PSTATE/serve-env" >"$PSTATE/serve-stub"
	chmod +x "$PSTATE/serve-stub"
}
run_start() {
	serve_stub
	DVTEE_INSECURE_HTTP=true DVTEE_ALLOW_DEPOSITS=true DVTEE_DATA=$PSTATE/data \
		DVTEE_BIN=$PSTATE/serve-stub "$START" >"$PSTATE/start-out" 2>&1
}
check "start: runs" run_start
args=$(tr '\n' ' ' <"$PSTATE/serve-args" 2>/dev/null)
check "start: tee platform" grep -q -- '--platform tee' <<<"$args"
check "start: listeners" grep -q -- '--listen 0.0.0.0:9000 --public-listen 0.0.0.0:9001' <<<"$args"
check "start: devnet network" grep -q -- "--network $PSTATE/data/config/config.yaml --genesis-validators-root $GVR" <<<"$args"
check "start: tls sans" grep -q -- '--tls-san localhost,127.0.0.1' <<<"$args"
check "start: no DVTEE_* in the environment" fails grep -q '^DVTEE_' "$PSTATE/serve-env"
check "start: debug log level" grep -qx 'RUST_LOG=dvtee=debug,tower_http=info' "$PSTATE/serve-env"

prov_env hoodi
echo '{"lock_hash":"0x00"}' >"$T/lock.json"
echo "vc $(printf 'a%.0s' {1..40})" >"$T/tokens.txt"
"$MKDISK" -o "$PSTATE/prov.img" -k "$KEYS" -n hoodi -K /dev/null -L "$T/lock.json" -T "$T/tokens.txt" 2>/dev/null
check "provision: preset network accepted" run_provision "$PSTATE/prov.img"
check "start: runs (preset)" run_start
args=$(tr '\n' ' ' <"$PSTATE/serve-args" 2>/dev/null)
check "start: preset network" grep -q -- '--network hoodi' <<<"$args"
check "start: known clients" grep -q -- "--tls-known-clients $PSTATE/data/config/knownClients.txt" <<<"$args"
check "start: cluster lock" grep -q -- "--cluster-lock $PSTATE/data/config/cluster-lock.json" <<<"$args"
check "start: auth tokens" grep -q -- "--auth-token-file $PSTATE/data/config/tokens.txt" <<<"$args"
check "start: default log level" grep -qx 'RUST_LOG=dvtee=info,tower_http=warn' "$PSTATE/serve-env"

# Hostile archives: each must be rejected and leave no marker.
reject() { # description, archive
	prov_env "r$RANDOM"
	if run_provision "$2"; then bad "provision rejects $1"; elif [[ -e $PSTATE/data/provisioned ]]; then bad "provision rejects $1 (marker left)"; else ok "provision rejects $1"; fi
}
good_tree() { # a valid layout in $1
	mkdir -p "$1/validator_keys" "$1/config"
	cp "$KEYS"/keystore-0.* "$1/validator_keys/"
	echo hoodi >"$1/config/network"
}

d=$T/h-symlink; good_tree "$d"; ln -s /etc/shadow "$d/config/knownClients.txt"
tar_of "$d" "$T/symlink.tar" validator_keys config
reject "a symlink" "$T/symlink.tar"

d=$T/h-hardlink; good_tree "$d"; ln "$d/config/network" "$d/config/knownClients.txt"
tar_of "$d" "$T/hardlink.tar" validator_keys config
reject "a hard link" "$T/hardlink.tar"

d=$T/h-extra; good_tree "$d"; echo 'DVTEE_INSECURE_HTTP=true' >"$d/config/env"
tar_of "$d" "$T/extra.tar" validator_keys config
reject "an unexpected file" "$T/extra.tar"

d=$T/h-dotdot; good_tree "$d/inner"; mkdir -p "$d/x"; echo hoodi >"$d/x/network"
tar_of "$d/inner" "$T/dotdot.tar" --transform 's|^config/network$|config/../../x/network|' validator_keys config
reject "a ../ path" "$T/dotdot.tar"

d=$T/h-abs; good_tree "$d"
tar_of "$d" "$T/abs.tar" --absolute-names --transform 's|^config/network$|/tmp/network|' validator_keys config
reject "an absolute path" "$T/abs.tar"

d=$T/h-nopass; good_tree "$d"; rm "$d/validator_keys/keystore-0.txt"
tar_of "$d" "$T/nopass.tar" validator_keys config
reject "a keystore without a password file" "$T/nopass.tar"

d=$T/h-net; good_tree "$d"; echo 'hoodi --insecure-http' >"$d/config/network"
tar_of "$d" "$T/net.tar" validator_keys config
reject "an invalid network" "$T/net.tar"

d=$T/h-gvr; good_tree "$d"; echo "$GVR" >"$d/config/genesis-validators-root"
tar_of "$d" "$T/gvr.tar" validator_keys config
reject "a genesis root with a preset network" "$T/gvr.tar"

d=$T/h-sans; good_tree "$d"; echo 'localhost --insecure-http' >"$d/config/tls-sans"
tar_of "$d" "$T/sans.tar" validator_keys config
reject "invalid TLS SANs" "$T/sans.tar"

d=$T/h-nokeys; mkdir -p "$d/validator_keys" "$d/config"; echo hoodi >"$d/config/network"
tar_of "$d" "$T/nokeys.tar" validator_keys config
reject "no keystores" "$T/nokeys.tar"

reject "a missing disk" "$T/does-not-exist"
head -c 4096 /dev/urandom >"$T/garbage.img"
reject "garbage" "$T/garbage.img"

echo
echo "$pass passed, $fail failed"
((fail == 0))
