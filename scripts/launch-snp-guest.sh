#!/bin/bash
# Launches the dvtee guest under QEMU/KVM as an SEV-SNP guest, with the
# parameters in snp-params.env (the same ones expected-measurement.sh uses).
#
#   scripts/launch-snp-guest.sh --data data.img [--provision prov.img]
#       [--uki out/image/dvtee.efi] [--image out/image/dvtee.raw]
#       [--ovmf out/ovmf/OVMF.fd]
#       [--signer-addr 127.0.0.1:19000] [--public-addr 127.0.0.1:19001]
#       [--serial-log FILE] [--qmp SOCKET] [--append CMDLINE] [--print]
#
#   --uki/--image the UKI and the root disk image from the same build (the
#                 UKI's verity root hash must match the image)
#   --data        raw data disk (serial dvtee-data). For a new guest,
#                 create a blank one: truncate -s 1G data.img
#   --provision   provisioning disk from make-provision-disk.sh, read-only
#                 (serial dvtee-prov). Only read on the first boot.
#   --signer-addr host address forwarded to the guest's signing port 9000
#   --public-addr host address forwarded to the public port 9001
#                 (health and attestation)
#   --qmp         QMP socket, to stop the guest (always a power cut: the image
#                 has no ACPI power-button handling):
#                 printf '%s' '{"execute":"qmp_capabilities"}{"execute":"quit"}' | socat - UNIX-CONNECT:SOCKET
#   --append      NEGATIVE TESTS ONLY: a host-supplied command line changes
#                 the measurement, so the data disk must not open
#   --print       print the QEMU command and exit
#
# Overrides: QEMU (binary), and any SNP_* from snp-params.env. Changing
# SNP_VCPUS, SNP_VCPU_TYPE or SNP_GUEST_FEATURES changes MEASUREMENT; changing
# SNP_POLICY changes the sealing key. The guest powers off on any boot or
# unlock failure, and QEMU exits (-no-reboot), so a guest reboot also ends
# QEMU: relaunch with the same disks.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source-path=SCRIPTDIR source=snp-params.env
. "$ROOT/scripts/snp-params.env"

QEMU=${QEMU:-qemu-system-x86_64}
UKI=$ROOT/out/image/dvtee.efi
IMAGE=$ROOT/out/image/dvtee.raw
OVMF=$ROOT/out/ovmf/OVMF.fd
DATA=''
PROV=''
SIGNER_ADDR=127.0.0.1:19000
PUBLIC_ADDR=127.0.0.1:19001
SERIAL=''
QMP=''
APPEND=''
HAVE_APPEND=''
PRINT=''
while (($#)); do
	case $1 in
	--data) DATA=$2; shift 2 ;;
	--provision) PROV=$2; shift 2 ;;
	--uki) UKI=$2; shift 2 ;;
	--image) IMAGE=$2; shift 2 ;;
	--ovmf) OVMF=$2; shift 2 ;;
	--signer-addr) SIGNER_ADDR=$2; shift 2 ;;
	--public-addr) PUBLIC_ADDR=$2; shift 2 ;;
	--serial-log) SERIAL=$2; shift 2 ;;
	--qmp) QMP=$2; shift 2 ;;
	--append) APPEND=$2; HAVE_APPEND=1; shift 2 ;;
	--print) PRINT=1; shift ;;
	*) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" >&2; exit 2 ;;
	esac
done
[[ -n $DATA ]] || { echo "--data is required" >&2; exit 2; }
hostport() { [[ $1 =~ ^([0-9.]+):([0-9]+)$ ]] || { echo "bad address $1 (want IP:PORT)" >&2; exit 2; }; }
hostport "$SIGNER_ADDR"
hostport "$PUBLIC_ADDR"

VIRTIO=disable-legacy=on,iommu_platform=true
# shellcheck disable=SC2054 # commas are QEMU option syntax
cmd=(
	"$QEMU"
	-name dvtee,debug-threads=on
	-enable-kvm
	-nodefaults -display none -vga none -no-reboot
	-machine "q35,confidential-guest-support=sev0,memory-backend=ram0,vmport=off"
	-object "memory-backend-memfd,id=ram0,size=$SNP_MEMORY,share=true,prealloc=false"
	-object "sev-snp-guest,id=sev0,cbitpos=$SNP_CBITPOS,reduced-phys-bits=$SNP_REDUCED_PHYS_BITS,policy=$SNP_POLICY,kernel-hashes=on"
	-cpu "$SNP_VCPU_TYPE"
	-smp "$SNP_VCPUS"
	-m "$SNP_MEMORY"
	-bios "$OVMF"
	-kernel "$UKI"
)
[[ -z $HAVE_APPEND ]] || cmd+=(-append "$APPEND")
cmd+=(
	-netdev "user,id=net0,ipv6=off,hostfwd=tcp:$SIGNER_ADDR-:9000,hostfwd=tcp:$PUBLIC_ADDR-:9001"
	-device "virtio-net-pci,netdev=net0,$VIRTIO,romfile="
	-drive "if=none,id=root,file=$IMAGE,format=raw,readonly=on"
	-device "virtio-blk-pci,drive=root,serial=dvtee-root,$VIRTIO"
	-drive "if=none,id=data,file=$DATA,format=raw"
	-device "virtio-blk-pci,drive=data,serial=dvtee-data,$VIRTIO"
)
if [[ -n $PROV ]]; then
	cmd+=(
		-drive "if=none,id=prov,file=$PROV,format=raw,readonly=on"
		-device "virtio-blk-pci,drive=prov,serial=dvtee-prov,$VIRTIO"
	)
fi
[[ -z $QMP ]] || cmd+=(-qmp "unix:$QMP,server=on,wait=off")
if [[ -n $SERIAL ]]; then
	cmd+=(-serial "file:$SERIAL")
else
	cmd+=(-serial stdio)
fi

if [[ -n $PRINT ]]; then
	printf '%q ' "${cmd[@]}"; echo
	exit 0
fi
for f in "$UKI" "$IMAGE" "$OVMF" "$DATA" ${PROV:+"$PROV"}; do
	[[ -f $f ]] || { echo "missing $f" >&2; exit 1; }
done
exec "${cmd[@]}"
