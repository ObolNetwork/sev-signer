#!/bin/bash
# Builds the TEMPORARY provisioning disk the guest reads once, on first boot
# (image/mkosi.extra/usr/lib/dvtee/provision): a plain tar archive used
# as a raw virtio disk with serial=dvtee-prov.
#
# WARNING: the host can read this disk, keystores and passwords included.
# Use it for devnet and test keys only.
#
#   scripts/make-provision-disk.sh -o prov.img -k validator_keys/ -n hoodi
#   scripts/make-provision-disk.sh -o prov.img -k validator_keys/ \
#       -c config.yaml -g 0x<genesis validators root> [-s localhost,127.0.0.1] \
#       [-K knownClients.txt] [-L cluster-lock.json] [-T tokens.txt] [-l debug]
#
# -k takes charon's validator_keys/ layout: keystore-N.json with keystore-N.txt.
set -euo pipefail

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" >&2; exit 2; }

out='' keys='' net='' cfg='' gvr='' sans='' known='' lock='' tokens='' level=''
while getopts o:k:n:c:g:s:K:L:T:l:h opt; do
	case $opt in
	o) out=$OPTARG ;;
	k) keys=$OPTARG ;;
	n) net=$OPTARG ;;
	c) cfg=$OPTARG ;;
	g) gvr=$OPTARG ;;
	s) sans=$OPTARG ;;
	K) known=$OPTARG ;;
	L) lock=$OPTARG ;;
	T) tokens=$OPTARG ;;
	l) level=$OPTARG ;;
	*) usage ;;
	esac
done
[[ -n $out && -d $keys ]] || usage
if [[ -n $cfg ]]; then
	[[ -z $net && -f $cfg && $gvr =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "-c needs -g 0x<64 hex> and no -n" >&2; exit 2; }
	net=config.yaml
else
	[[ $net =~ ^(mainnet|hoodi|sepolia)$ && -z $gvr ]] || { echo "-n must be mainnet, hoodi or sepolia (or use -c and -g)" >&2; exit 2; }
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/validator_keys" "$stage/config"
n=0
for ks in "$keys"/keystore-*.json; do
	[[ -f $ks ]] || continue
	base=$(basename "$ks" .json)
	[[ $base =~ ^keystore-[0-9]{1,5}$ ]] || { echo "unexpected keystore name $ks" >&2; exit 1; }
	[[ -f $keys/$base.txt ]] || { echo "$ks has no $base.txt" >&2; exit 1; }
	cp "$ks" "$keys/$base.txt" "$stage/validator_keys/"
	n=$((n + 1))
done
((n > 0)) || { echo "no keystore-*.json in $keys" >&2; exit 1; }

printf '%s\n' "$net" >"$stage/config/network"
if [[ $net == config.yaml ]]; then
	cp "$cfg" "$stage/config/config.yaml"
	printf '%s\n' "$gvr" >"$stage/config/genesis-validators-root"
fi
[[ -z $sans ]] || printf '%s\n' "$sans" >"$stage/config/tls-sans"
[[ -z $known ]] || cp "$known" "$stage/config/knownClients.txt"
[[ -z $lock ]] || cp "$lock" "$stage/config/cluster-lock.json"
[[ -z $tokens ]] || cp "$tokens" "$stage/config/tokens.txt"
[[ -z $level ]] || printf '%s\n' "$level" >"$stage/config/log-level"
chmod -R u=rwX,go= "$stage"
# The same checks the guest runs, so a bad disk fails here rather than at boot.
# shellcheck source-path=SCRIPTDIR source=../image/mkosi.extra/usr/lib/dvtee/lib.sh
. "$(dirname "$0")/../image/mkosi.extra/usr/lib/dvtee/lib.sh"
dvtee_check_config "$stage" || exit 1

tar --create --format=gnu --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name \
	--directory "$stage" --file "$out" validator_keys config
echo "wrote $out: $n keystore(s), network $net. The host can read it: test keys only." >&2
