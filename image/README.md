# Guest image

The SEV-SNP guest that runs dvtee, built with [mkosi](https://github.com/systemd/mkosi). It
replaces the 2024 Alpine image (`Dockerfile`, `build_kernel.sh`, `linux-mainline-sev-src/`,
`vm-scripts/`), which is unsafe for keys (ROADMAP.md, Findings). Those files stay for reference
only.

**Status: written, not yet built or booted.** The boot scripts have unit tests. Everything else
waits for the first session on SNP hardware: [docs/hardware-runbook.md](../docs/hardware-runbook.md).

## Boot chain

```
OVMF (ovmf/, AmdSevX64)          measured by the AMD secure processor
  └─ -kernel dvtee.efi      UKI; kernel-hashes=on puts its hash in measured memory,
                                 and OVMF refuses a UKI or command line that doesn't match
       └─ systemd-stub → Linux + initrd + command line (all inside the UKI)
            initrd: dm-verity root from roothash= on the command line
                    dvtee-unlock: open (or create) the sealed data disk, or power off
            root:   dvtee-provision (first boot only), then dvtee
```

Everything the guest runs is in the launch measurement: the firmware, and the UKI's kernel, initrd
and command line. The root filesystem is tied in through the verity root hash on that command line.

## Disks

| Disk | virtio serial | Contents | Trust |
|---|---|---|---|
| `dvtee.raw` | any | erofs root + dm-verity hash partition | verified against the measured root hash |
| data (`truncate -s 1G data.img`) | `dvtee-data` | LUKS2, `aegis128-random` with AEAD integrity, 4 KiB sectors, ext4 | sealed: only this image, policy and chip can open it |
| provisioning | `dvtee-prov` | tar archive: keystores and settings | **host-readable; first boot only; temporary** |

The data disk holds everything the signer writes: keys, slashing protection and its TLS key
(`/var/lib/dvtee`). Everything else is read-only or in memory (`systemd.volatile=state`).

## Sealing

`dvtee-unlock` runs in the initrd:

* The key is `dvtee sealing-key --purpose data-disk --snp-min-tcb <pinned> --snp-vmpl 0`.
* That key is an SNP derived key: VCEK root, with MEASUREMENT, POLICY and the pinned minimum
  TCB_VERSION mixed in (`signer/src/platform.rs`).
* The minimum TCB is a build input (`SNP_MIN_TCB`), stored in the measured initrd.
* Firmware updates above the minimum keep the key. A rollback below it can't derive the key.
* A different measurement, policy or chip gets a different key, and the disk stays closed.

Decision table:

| Data disk | Action |
|---|---|
| LUKS2 header | open with the sealing key; on failure power off, never reformat |
| no header, first 16 MiB zero | first boot: `luksFormat`, open, `mkfs.ext4` |
| anything else | refuse, power off |

* **Key checks.** The key must be exactly 32 bytes before cryptsetup sees it.
* **Header checks.** The LUKS header is not authenticated, so after opening the script checks the
  mapping really is `aegis128-random` with AEAD integrity.
* **PBKDF.** PBKDF2 at 1000 iterations: the key is already 256 random bits, and Argon2's memory cost
  would only slow the boot.

## No way in

* There is no getty, sshd or password login. Every getty unit, `getty.target` and `debug-shell` are
  masked, and the getty generator is off (`systemd.getty_auto=0`).
* `emergency.service` and `rescue.service`, in the initrd and in the root, are replaced by units that
  power off.
* The kernel command line is measured. Without Secure Boot, systemd-stub still accepts a host
  `-append`, but that changes MEASUREMENT and with it the disk key.
* systemd ignores SMBIOS and fw_cfg credentials, and SMBIOS command-line extensions, when it detects
  a confidential VM. This was checked in the systemd v257 source.
* AmdSevX64 OVMF has no persistent variable store for the host to fill.
* `lockdown=confidentiality`, `module.sig_enforce=1`, no core dumps, and `systemd.gpt_auto=0`, so a
  partition the host adds is never activated.
* Logs go to the serial console, initrd included. That is the only output.
* `bash` and `dash` are still in the image, because the boot scripts need them. Nothing gives the
  host a way to reach them.

## The signer

* `dvtee.service` is the only network listener: 9000 for signing and 9001 public (health and
  attestation).
* Its flags come from settings provisioned onto the sealed disk, never from the host. `start`
  validates them and runs the signer under `env -i`, so no `DVTEE_*` variable gets through.
* It runs as uid 0 with no capabilities, because configfs-tsm report entries are root-owned.
* Its file system view is read-only, except the data dir and `/sys/kernel/config/tsm/report`.
* It has a syscall filter, no new privileges and no core dumps.

## Provisioning (temporary)

On the first boot only, `dvtee-provision` reads a tar archive from the `dvtee-prov` disk.

* **What it accepts.** Keystores in charon's `validator_keys/` layout, the network (a preset, or a
  devnet `config.yaml` with its genesis validators root), and optionally TLS SANs, pinned client
  certificates and a log level.
* **How it checks them.** Only whitelisted names, regular files and fixed formats pass. It copies them
  to the sealed disk and writes a `provisioned` marker last. After that the disk is never read again.
* **The host can read this disk.** It is for test and devnet keys only. The plan is key import over
  attested TLS (keymanager API) or DKG in the guest (ROADMAP.md, design choice 1).

`scripts/make-provision-disk.sh` builds the archive and runs the guest's own checks on it.

## Build

```sh
make ovmf                                   # out/ovmf/OVMF.fd (pinned edk2)
SNP_MIN_TCB=0x<16 hex digits> make image     # out/image/
make image-measure                           # expected MEASUREMENT, as JSON
make image-test                              # unit tests for the boot scripts
```

`image/build.sh` builds a static dvtee in `rust:1.100.0-slim-trixie` (pinned by digest,
`cargo --locked`). It then runs mkosi v27.1, pinned by commit. Pins:

| Input | Pin |
|---|---|
| Packages and tools tree | Debian 13 (trixie), `snapshot.debian.org` `20261120T000000Z` |
| Kernel | `linux-image-6.12.117+deb13-cloud-amd64` (from that snapshot) |
| Timestamps | `SourceDateEpoch=1795132800` (2026-11-20) |
| Partition UUIDs, verity salt | `Seed=` in `mkosi.conf` |
| mkosi | v27.1, `ecf7f5702bb2052b7a69cab3fe7d37bc3b9ad77b` |
| Rust | 1.100.0, image digest in `signer.Dockerfile`; crates by `Cargo.lock` |
| sev-snp-measure | 0.0.13, by wheel hash (`ovmf/requirements-measure.txt`) |

`scripts/snp-params.env` holds the launch parameters. Both `scripts/expected-measurement.sh` and
`scripts/launch-snp-guest.sh` read it, so the measurement and the launch use the same vCPU count,
vCPU type, guest features and policy.

Profiles: `--profile debug` adds verbose systemd logging. `--profile variant` adds one inert
command line word, for the negative test. Both change the measurement, so neither can open a release
guest's disk.

## Known limitations

* **Rollback.** The host can restore an older copy of the data disk, or attach a blank one. A blank
  disk gives a fresh, empty signer. An old copy rolls back slashing watermarks: the known gap that
  design choice 5 addresses.
* **Kernel.** The kernel is Debian's signed cloud build, pinned by version, not built from source
  here.
* **ACPI tables.** QEMU supplies them and they are not measured. This is true of all SNP guests
  without an SVSM.
* **No clean shutdown.** There is no logind or D-Bus, so an ACPI power-off is ignored. Every stop is a
  power cut. The signer fsyncs each watermark before it releases a signature, so a cut loses nothing
  signed.
* **TCB check in the verifier.** The pinned minimum TCB protects the disk key. The verifier doesn't
  check the report's TCB yet.
