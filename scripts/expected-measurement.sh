#!/bin/bash
# Prints the expected SEV-SNP launch measurement (the report's MEASUREMENT)
# for the guest image and the launch parameters in snp-params.env.
#
#   scripts/expected-measurement.sh [--uki out/image/dvtee.efi]
#       [--ovmf out/ovmf/OVMF.fd] [--append CMDLINE] [--json] [--dry-run]
#
# Inputs that must match the launch exactly (launch-snp-guest.sh uses the
# same snp-params.env):
#   - OVMF.fd bytes (make ovmf), passed with -bios;
#   - the UKI bytes, passed with -kernel; no -initrd;
#   - the -append string: none by default (the UKI carries its own command
#     line). Only the negative tests pass one;
#   - vCPU count and type, and the VMSA guest features;
#   - VMM type QEMU, and sev-snp-guest with kernel-hashes=on.
# The guest policy is not part of MEASUREMENT, but it must still match: it is
# in the report and in the sealing key.
#
# sev-snp-measure is the version pinned in ovmf/requirements-measure.txt
# (0.0.13). By default it runs from the OVMF builder image (make ovmf-image);
# set SEV_SNP_MEASURE to a local install of the same version instead.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source-path=SCRIPTDIR source=snp-params.env
. "$ROOT/scripts/snp-params.env"

UKI=$ROOT/out/image/dvtee.efi
OVMF=$ROOT/out/ovmf/OVMF.fd
APPEND=
JSON=
DRY=
while (($#)); do
	case $1 in
	--uki) UKI=$2; shift 2 ;;
	--ovmf) OVMF=$2; shift 2 ;;
	--append) APPEND=$2; shift 2 ;;
	--json) JSON=1; shift ;;
	--dry-run) DRY=1; shift ;;
	*) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" >&2; exit 2 ;;
	esac
done

measure_args=(--mode snp --vmm-type QEMU --vcpus "$SNP_VCPUS" --vcpu-type "$SNP_VCPU_TYPE"
	--guest-features "$SNP_GUEST_FEATURES")
[[ -z $APPEND ]] || measure_args+=(--append "$APPEND")

if [[ -n ${SEV_SNP_MEASURE:-} ]]; then
	cmd=("$SEV_SNP_MEASURE" "${measure_args[@]}" --ovmf "$OVMF" --kernel "$UKI")
else
	cmd=(docker run --rm --network none
		-v "$(realpath -m "$UKI"):/in/kernel:ro" -v "$(realpath -m "$OVMF"):/in/OVMF.fd:ro"
		--entrypoint sev-snp-measure "${OVMF_BUILDER_IMAGE:-obolnetwork/ovmf-builder}"
		"${measure_args[@]}" --ovmf /in/OVMF.fd --kernel /in/kernel)
fi
if [[ -n $DRY ]]; then
	printf '%q ' "${cmd[@]}"; echo
	exit 0
fi
for f in "$UKI" "$OVMF"; do
	[[ -f $f ]] || { echo "missing $f" >&2; exit 1; }
done

m=$("${cmd[@]}")
[[ $m =~ ^[0-9a-f]{96}$ ]] || { echo "unexpected sev-snp-measure output: $m" >&2; exit 1; }
if [[ -z $JSON ]]; then
	echo "$m"
	exit 0
fi
sha() { sha256sum "$1" | cut -d' ' -f1; }
jq -n --arg m "$m" --arg ovmf "$(sha "$OVMF")" --arg uki "$(sha "$UKI")" --arg append "$APPEND" \
	--argjson vcpus "$SNP_VCPUS" --arg type "$SNP_VCPU_TYPE" --arg features "$SNP_GUEST_FEATURES" \
	--arg policy "$SNP_POLICY" \
	'{measurement: $m, ovmf_sha256: $ovmf, uki_sha256: $uki, append: $append, vcpus: $vcpus,
	  vcpu_type: $type, guest_features: $features, vmm_type: "QEMU", policy: $policy,
	  sev_snp_measure: "0.0.13"}'
