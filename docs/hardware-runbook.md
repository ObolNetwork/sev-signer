# Hardware runbook: the dvtee guest on a bare-metal SEV-SNP host

This is the first run of the mkosi guest image (`image/`) on real AMD SEV-SNP hardware. The aim is to
run it as written, without development on the box. If something in the image has to change, record
the diff and the new measurement, and keep going where you can.

**You need:**

* a bare-metal AMD EPYC host, Milan (7xx3) or later, with root and BIOS or BMC access;
* about 16 GB of RAM: the guest takes 2 GB, the devnet in part D about 4 GB;
* about 30 GB of disk;
* half a day.

**Keys.** Every key used here is a public test key or a devnet key. The provisioning disk is
host-readable by design (`image/README.md`). Never use it for real keys.

**Build ahead.** Section 2 needs no SNP hardware, only Docker, network and user namespaces. Run it
on any Linux host before the box arrives, so the build problems are solved before the hardware
session starts.

**Stopping the guest.** The image has no ACPI power-button handling (logind needs D-Bus, which isn't
installed). Every stop is therefore a power cut: QMP `quit` or killing QEMU. The signer fsyncs each
slashing watermark before it releases a signature, and section 5.2 tests exactly this case.

**Variables used below:**

```sh
R=~/dvtee                 # this repo, at the commit under test
RUN=~/snp-run                  # scratch dir for disks, logs and evidence
S=$R/out/image/dvtee      # static dvtee from the image build (runs on the host too)
```

## 1. Host

### 1.1 BIOS

The names vary by vendor (AMD CBS menus, usually under CPU Common Options and NBIO). Set:

| Setting | Value |
|---|---|
| SMEE (Secure Memory Encryption Enable) | Enabled |
| SEV-SNP Support | Enabled |
| SNP Memory (RMP Table) Coverage | Enabled |
| SEV-ES ASID Space Limit | above 1, e.g. 100 (ASIDs below it are for SEV-ES/SNP guests) |
| IOMMU | Enabled |

* **No BIOS access?** Ask the provider for these settings. `snphost ok` (1.4) shows what is missing.
* **Record:** the board vendor, model and BIOS version (`scripts/host-facts.sh` in 1.5 collects
  them).

### 1.2 OS, kernel and QEMU

* **Upstream minimums.** KVM's SNP host support landed in Linux 6.11, and QEMU's SNP support in
  9.1.
* **Recommended OS: Debian 13 (trixie).** On 2026-11-20 it shipped kernel 6.12.117 and QEMU 10.0.
  Both have upstream SNP host support, and the guest is built from the same Debian release.
* **Other distributions** work if they meet both minimums. Record what you use.
* **Distribution QEMU is fine.** No AMD fork is needed; the old `vm-scripts/run.sh` path
  (`/root/AMDSEV/qemu`) is not used.

```sh
apt install qemu-system-x86 qemu-utils docker.io git python3 python3-venv jq curl openssl socat \
    xxd binutils debian-archive-keyring apt-utils cargo
```

* `cargo` is only for building `snphost` and `snpguest`. The image build uses its own pinned Rust in
  Docker.
* No extra kernel parameters should be needed. If 1.3 shows SNP off, add
  `kvm_amd.sev=1 kvm_amd.sev_es=1 kvm_amd.sev_snp=1`, reboot and record it.

### 1.3 Check that SNP is live

```sh
dmesg | grep -i -E 'sev|snp|rmp'               # expect "SEV-SNP API:<major>.<minor>" from ccp and an RMP table
cat /sys/module/kvm_amd/parameters/sev_snp     # Y
cat /sys/module/kvm_amd/parameters/sev_es      # Y
ls -l /dev/sev                                 # present
```

* **SNP firmware.** Record the API version from `dmesg`. Linux needs at least 1.51, and older
  firmware has known issues, so newer is better.
* **Firmware updates** come from a BIOS update, or from the SEV firmware file in `/lib/firmware/amd/`
  (linux-firmware) loaded by `ccp`. Record which, if you update.

### 1.4 Tools

```sh
cargo install --locked snphost --version 0.9.0
cargo install --locked snpguest --version 0.11.0
snphost ok                  # every check should pass; record the output
snphost show tcb            # record
```

### 1.5 Record host facts

```sh
mkdir -p $RUN && sudo $R/scripts/host-facts.sh $RUN/host-facts
```

## 2. Build

```sh
git clone https://github.com/ObolNetwork/dvtee $R && cd $R && git checkout <commit under test>
make ovmf                                    # out/ovmf/OVMF.fd
sha256sum out/ovmf/OVMF.fd; cat out/ovmf/OVMF.snp-ovmf-hash
make image-test                              # boot-script unit tests: expect "0 failed"
```

* **OVMF check.** Compare the `OVMF.fd` hash with the `ovmf` CI run for the same commit. They should
  be identical.
* **Discovery build.** The first image is built with minimum TCB 0. It is only used to read the
  platform's TCB (section 3).

```sh
SNP_MIN_TCB=0x0000000000000000 make image     # out/image/: dvtee.efi, .raw, SHA256SUMS, BUILDINFO
mkdir -p $RUN/image-discovery                 # section 4 overwrites out/image
cp out/image/{dvtee,dvtee.efi,dvtee.raw,dvtee.roothash,SHA256SUMS,BUILDINFO} $RUN/image-discovery/
cp out/image/SHA256SUMS $RUN/SHA256SUMS.discovery
```

**Reproducibility check (run it while doing section 3).** Rebuild from a clean tree with the same
`SNP_MIN_TCB`. Every line of `SHA256SUMS` should match. A mismatch is a finding: record it, with
`diffoscope` output if you have time. Keep the first build either way.

```sh
OUT_DIR=$RUN/rebuild SNP_MIN_TCB=0x0000000000000000 image/build.sh
diff $RUN/SHA256SUMS.discovery $RUN/rebuild/SHA256SUMS && echo REPRODUCIBLE
```

Expected measurement:

```sh
make ovmf-image                                # the pinned sev-snp-measure lives in this image
scripts/expected-measurement.sh --uki $RUN/image-discovery/dvtee.efi --json > $RUN/expected-discovery.json
cat $RUN/expected-discovery.json               # .measurement is M_DISC
```

## 3. First boot and attestation (test a), discovery image

```sh
mkdir -p $RUN/disc && cd $RUN/disc
$R/scripts/make-provision-disk.sh -o prov.img -k $R/signer/tests/vectors/keystores -n hoodi -l debug
truncate -s 1G data.img
$R/scripts/launch-snp-guest.sh --uki $RUN/image-discovery/dvtee.efi \
    --image $RUN/image-discovery/dvtee.raw --data data.img --provision prov.img \
    --serial-log serial.log --qmp qmp.sock &
tail -f serial.log
```

Expected on the serial console, in order:

1. The kernel reports SEV-SNP active (`Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`).
2. `dvtee-unlock: data disk ..., minimum TCB 0x0000000000000000`
3. `dvtee-unlock: first boot: creating the sealed data disk`, then `created and opened`. The
   integrity wipe of 1 GB takes a while.
4. `dvtee-provision: provisioned 2 keystore(s) ...`
5. dvtee's `dvtee serving` line.

If the guest powers off instead, the last lines say why. See Troubleshooting.

**Attestation (test a):**

```sh
NONCE=$(openssl rand -hex 32)
curl -sk "https://127.0.0.1:19001/api/v1/tee/attestation?nonce=$NONCE" > evidence.json
M_DISC=$(jq -r .measurement $RUN/expected-discovery.json)
$S verify-evidence --evidence evidence.json --nonce $NONCE --expected-measurement $M_DISC \
    --fetch-vcek | tee verify-evidence.txt
$R/scripts/snp-report-fields.py evidence.json | tee report-fields.txt
jq -r .tls_certificate evidence.json > cert.pem
curl -sf --cacert cert.pem https://127.0.0.1:19001/upcheck && echo PINNED
```

* **Expected `verify-evidence` result:**
  * provider `sev_guest`;
  * `report_data binding: OK`;
  * `debug policy: OK`;
  * `measurement: OK`;
  * the VCEK chain to AMD's pinned root and the report signature: OK.
* **The `-k` on the first fetch** is trust on first use. The binding check is what ties `cert.pem`
  to this report.
* **AMD chain.** `verify-evidence` checks the report signature with the VCEK, and the VCEK against
  AMD's pinned roots (Milan, Genoa, Turin). The VCEK comes from the evidence's certificate table when
  the host provides one, else from AMD's KDS (`--fetch-vcek`). KDS rate limits: on a 429, retry later
  or pass `--vcek certs/vcek.pem` from the snpguest step below. Also check with snpguest, as an
  independent second opinion:

```sh
jq -r .report evidence.json | sed 's/^0x//' | xxd -r -p > report.bin
snpguest fetch ca pem certs -r report.bin -e vcek
snpguest fetch vcek pem certs report.bin
snpguest verify certs certs
snpguest verify attestation certs report.bin | tee snpguest-verify.txt
```

**Pick the minimum TCB:**

```sh
MIN_TCB=$($R/scripts/snp-report-fields.py --min-tcb evidence.json); echo $MIN_TCB
```

* **Why this value.** It is the component-wise minimum of the reported and committed TCB, usually
  just the committed TCB. That's the lowest TCB the firmware will still accept. Pinning it means
  firmware updates keep the disk key, and nobody can roll the platform back below it and still derive
  the key.
* **Why not always the committed TCB.** When newer firmware was loaded but not committed, the
  reported TCB lags the committed one, and `verify-evidence --min-tcb` checks both. On the first
  hardware run (Milan, firmware 1.55.29 loaded from linux-firmware) the reported SNP SVN was 23 and the
  committed one 24, so pinning the committed value failed attestation.
* **Record** all four TCB values (current, reported, committed, launch) and the firmware version from
  `report-fields.txt`.

Stop the guest:

```sh
printf '%s' '{"execute":"qmp_capabilities"}{"execute":"quit"}' | socat - UNIX-CONNECT:qmp.sock
```

## 4. Release image with the pinned minimum TCB

```sh
cd $R
SNP_MIN_TCB=$MIN_TCB make image
scripts/expected-measurement.sh --json > $RUN/expected.json; M=$(jq -r .measurement $RUN/expected.json)
mkdir -p $RUN/rel && cd $RUN/rel
$R/scripts/make-provision-disk.sh -o prov.img -k $R/signer/tests/vectors/keystores -n hoodi -l debug
truncate -s 1G data.img
$R/scripts/launch-snp-guest.sh --data data.img --provision prov.img --serial-log serial-1.log --qmp qmp.sock &
```

When `dvtee serving` appears:

1. Repeat the attestation block from section 3 with `$M`, adding `--min-tcb $MIN_TCB`.
2. Then sign. The guest runs on Hoodi with the start floor on, so the test vector's old epoch is
   refused. Sign live instead, against a reference signer on the host: the same keystore, an
   insecure-dev build, and the floor off.

```sh
(cd $R/signer && cargo build --locked --features insecure-dev)
$R/signer/target/debug/dvtee serve --platform insecure-dev --insecure-dev-root-key $RUN/ref.key \
  --network hoodi --anti-rollback false --keystores-dir $R/signer/tests/vectors/keystores \
  --data-dir $RUN/ref --listen 127.0.0.1:29200 > $RUN/ref.log 2>&1 &
export SIGN_CHECK_LIVE=1 SIGN_CHECK_REF="https://127.0.0.1:29200 $RUN/ref/tls/cert.pem" SIGN_CHECK_STATE=$RUN/live.json
$R/scripts/sign-check.sh https://127.0.0.1:19000 cert.pem first     # 200 once past the floor; = reference
$R/scripts/sign-check.sh https://127.0.0.1:19000 cert.pem conflict  # 412 (slashing protection)
$R/scripts/sign-check.sh https://127.0.0.1:19000 cert.pem replay    # 200, identical re-sign
sha256sum cert.pem | tee cert.sha256
```

* **What `first` checks.**
  * It waits until the guest's start floor has passed, which takes up to about four epochs after boot,
    and records how long that took.
  * It signs an attestation for the current epoch with keystore-0.
  * The signature must equal the reference signer's byte for byte.
* **This also tests trusted time in the guest.** The guest reached a Roughtime quorum through the host's
  network. Record the `trusted time: start floor set` line from the serial log, and the number of
  servers that agreed.
* **Without the floor.** The original vector check, `sign-check.sh` without `SIGN_CHECK_LIVE`, only
  works on a signer without the start floor (a devnet network).

## 5. Seal and unseal (test b)

**5.1 Stop and relaunch.** Keep the provisioning disk attached, to show it is ignored after the first
boot.

```sh
printf '%s' '{"execute":"qmp_capabilities"}{"execute":"quit"}' | socat - UNIX-CONNECT:qmp.sock
$R/scripts/launch-snp-guest.sh --data data.img --provision prov.img --serial-log serial-2.log --qmp qmp.sock &
```

* **Expected serial output:**
  * `dvtee-unlock: opened`, not `created`;
  * no `dvtee-provision` line;
  * `dvtee serving`.
* **Then:**
  * fetch evidence again; the TLS cert's sha256 must equal `cert.sha256`, because the TLS key lives on
    the sealed disk;
  * run `sign-check.sh ... conflict`: expect 412. After a restart the start floor refuses that epoch
    whatever the disk says, so this shows the refusal, not the watermark. The cert check above shows
    the sealed disk persisted;
  * run `sign-check.sh ... first`: once past the new floor, a new epoch signs and matches the
    reference.

**5.2 Power cut.** Right after a signing request, kill QEMU. To the guest, that is a power cut.

```sh
$R/scripts/sign-check.sh https://127.0.0.1:19000 cert.pem first; pkill -9 -f 'qemu-system-x86_64 -name dvtee'
$R/scripts/launch-snp-guest.sh --data data.img --serial-log serial-3.log --qmp qmp.sock &
```

* **Expected:** the disk opens, fsck is clean or repairs the journal, and `conflict` gives 412.
* **Record** any dm-integrity or ext4 messages.

**5.3 Host reboot.**

* Stop the guest, reboot the host, and repeat 1.3.
* Relaunch as in 5.2. Expected: the disk opens and `conflict` gives 412. This shows the derived key
  doesn't change across host reboots on the same chip and TCB.

## 6. Negative tests (test c)

Each test below launches against the release `data.img` from sections 4 and 5. Take a checksum first:

```sh
cd $RUN/rel; sha256sum data.img > data.sha256
```

* **Expected for every test:**
  * the serial log shows a `dvtee-unlock: FAILED` line (normally `cannot open the data disk`);
  * the guest powers off on its own and QEMU exits;
  * `sha256sum -c data.sha256` still passes, so a failed open writes nothing.
* **For each test, record:**
  * the expected measurement (where it applies);
  * the last 30 serial lines;
  * the result of the checksum check.

| # | Change | How | Measurement |
|---|---|---|---|
| c1 | host command line | `--append "$(objcopy -O binary --only-section=.cmdline $R/out/image/dvtee.efi /dev/stdout \| tr -d '\0') dvtee.host=1"` | differs: `scripts/expected-measurement.sh --append "<same string>"` |
| c2 | image | `SNP_MIN_TCB=$MIN_TCB image/build.sh --profile variant`, then `--uki $R/out/image-variant/dvtee.efi --image $R/out/image-variant/dvtee.raw` | differs: `expected-measurement.sh --uki $R/out/image-variant/dvtee.efi` |
| c3 | vCPU count | `SNP_VCPUS=2 $R/scripts/launch-snp-guest.sh ...` | differs: `SNP_VCPUS=2 expected-measurement.sh` |
| c4 | guest policy | `SNP_POLICY=0x30001 $R/scripts/launch-snp-guest.sh ...` (ABI minor 1: same rules, different policy value) | **same** as `$M`; only the key differs |
| c5 | discovery image | `--uki $RUN/image-discovery/dvtee.efi --image $RUN/image-discovery/dvtee.raw` (min TCB 0) | `M_DISC` |

* **c1 detail.** Without Secure Boot, systemd-stub uses a host `-append` instead of the UKI's own
  command line. The measurement is what catches it. Say whether the guest booted as far as the unlock.
* **c4 detail.** If QEMU or the firmware refuses `0x30001`, record the error and try `0x70000`
  (migration agent allowed). c4 shows that POLICY is part of the key, not only of the report.

**Optional, to observe and record (not pass/fail):**

* **c6 tampered ciphertext.** Stop the guest and copy `data.img`. Overwrite 4 KiB at 64 MiB
  (`dd if=/dev/urandom of=data.img bs=4096 count=1 seek=16384 conv=notrunc`), then launch.
  dm-integrity should turn reads of that sector into I/O errors, not silent corruption. Record what
  happens, then restore the copy.
* **c7 rollback (the start floor). Pass/fail, though listed here.** Start from a fresh release
  guest, with the live-mode settings from section 4:
  1. provision it;
  2. stop it and copy `data.img` to `data.before`;
  3. relaunch, run `first` (200), then stop it;
  4. put `data.before` back and relaunch;
  5. run `conflict`.

  The rolled-back disk has no watermark for that epoch, so slashing protection alone would sign. It
  is expected to return **412 with "start floor" in the body**: the new boot's floor, from trusted
  time, is past the signed epoch. A 200 is a failure. Record the floor epoch from the serial log.

## 7. Devnet with node3 signing in the guest (test d)

This is the `e2e/devnet` harness. Nodes 0 to 2 keep local insecure-dev signers. Node3's Prysm VC signs
through the SNP guest.

* **Inside pod3,** a `socat` forwarder listens on `127.0.0.1:9000` and passes TCP to the guest's
  forwarded port. TLS still ends inside the guest.
* **The certificate** Prysm trusts is the one from the guest's attestation evidence.
* **Requirements:** see `e2e/devnet/README.md`. That means Kurtosis CLI 1.22.2, charon main from
  `e995d274` or later, and a host `dvtee` built with `--features insecure-dev`. Release and
  insecure-dev builds both come from the same commit.

```sh
cd $R
export CHARON=~/charon/charon DVTEE=$R/signer/target/debug/dvtee WORKDIR=$RUN/devnet-work
(cd signer && cargo build --locked --features insecure-dev)
e2e/devnet/devnet.sh up && e2e/devnet/devnet.sh keys && e2e/devnet/devnet.sh cluster
. $WORKDIR/env                                   # GVR

mkdir -p $RUN/dev && cd $RUN/dev
$R/scripts/make-provision-disk.sh -o prov.img -k $WORKDIR/cluster/node3/validator_keys \
    -c $WORKDIR/genesis/config.yaml -g $GVR -s localhost,127.0.0.1 -l debug
truncate -s 1G data.img
HOST_IP=$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)    # usually 172.17.0.1
$R/scripts/launch-snp-guest.sh --data data.img --provision prov.img \
    --signer-addr $HOST_IP:19000 --public-addr 127.0.0.1:19001 --serial-log serial.log --qmp qmp.sock &
```

* **Networking.** The guest's port 9000 is forwarded to `docker0`'s address, not `0.0.0.0`, so it is
  reachable from containers but not from the internet.
* **Firewall.** Containers on the Kurtosis network reach it through the host's INPUT chain. If a host
  firewall drops that traffic, allow TCP 19000 from the Docker bridges, and record it.

When the guest logs `dvtee serving`:

1. Run the attestation block from section 3, with `$M` from section 4 (same build).
2. Check that `pubkeys` in the evidence are node3's key shares: `jq .pubkeys evidence.json`.
3. Start the pods:

```sh
cd $R
export SIGNER3_REMOTE=$HOST_IP:19000 SIGNER3_CERT=$RUN/dev/cert.pem SIGNER3_LOG=$RUN/dev/serial.log
e2e/devnet/devnet.sh pods
SLOTS=96 e2e/devnet/devnet.sh wait
e2e/devnet/devnet.sh summary | tee $RUN/dev/summary.txt
e2e/devnet/devnet.sh checks  | tee $RUN/dev/checks.txt
```

* **Pass criteria:**
  * node3 shows signatures by kind, at least attestations, RANDAO and aggregation selection;
  * `rejected=0 refused=0` on every node;
  * no invalid-partial-signature lines from charon;
  * DV duties and proposals as in earlier runs (`results/016`).
* **Optional.** In the middle of `wait`, kill QEMU and relaunch without the provisioning disk. Record
  how long node3 is out and whether it resumes with no `refused` beyond the replays you expect.
* **Teardown:** run `e2e/devnet/devnet.sh down`, stop the guest, and delete
  `$RUN/devnet-work` (devnet key shares).

## 8. Results

Write `results/<NNN>-dvtee-snp-hardware.md`, with raw files in a directory of the same name.
Put commands' raw output in the raw directory, not just conclusions.

**Host and build:**

* `host-facts/`: the CPU model, BIOS version and settings, OS, kernel, QEMU, `snphost ok` and
  `show tcb`, and the SNP firmware version.
* The commit, `BUILDINFO`, and `SHA256SUMS` for the discovery build, the rebuild and the release
  build. Did the rebuild reproduce?
* The OVMF sha256 and SNP OVMF hash, compared with CI.

**Measurements and attestation:**

* For each image: the expected measurement JSON, the measurement from the report, and whether they
  match. If they didn't match, what made them match (guest features, vCPU type, ...).
* `report-fields.txt`, `verify-evidence.txt`, `snpguest-verify.txt`, and the `MIN_TCB` chosen.

**Tests:**

* Serial logs for every boot: discovery, release first boot, 5.1, 5.2, 5.3, and each negative test.
* `sign-check.sh` output for each step of section 5.
* A table for tests c1 to c5: expected measurement, outcome, and whether `data.img` was unchanged.
  Notes on c6 if you ran it, and the c7 result.
* Devnet: `summary.txt`, `checks.txt`, node3's counts and the guest serial log.

**Other:**

* Timings: image build, OVMF build, boot to `serving` on first and later boots, and the integrity
  wipe on first boot.
* Every deviation from this runbook, and every change to the image, with its diff.

**No secrets.** The keys are public test vectors and devnet keys, but don't paste keystores or
password files anyway.

## Troubleshooting

There is no shell in the guest. The serial log is all you get. Rebuild with `--profile debug` for
verbose systemd and udev logs; it has its own measurement.

| Symptom | Likely cause |
|---|---|
| mkosi: `userns_acquire_empty`, `OSError: [Errno -28]` or `unshare failed: No space left on device` | the host blocks user namespaces (`user.max_user_namespaces=0`, as Obol's host hardening sets on purpose). Don't relax it: build in CI (`.github/workflows/image.yml`, run on a branch or by `workflow_dispatch` with `snp_min_tcb`) and copy the artifacts to the host. The builds are reproducible, so `SHA256SUMS` from CI is what you'd have built |
| boot reaches `multi-user.target` but dvtee never starts; the serial log shows the data disk's fsck, then nothing | the root image lacks `dmsetup`'s udev rules, so systemd marks the initrd's dm devices not ready after switch-root and stops the data disk's mount. Fixed in `mkosi.conf`; to see it, boot with `--append "<the image's command line> systemd.log_level=debug systemd.log_target=console"` and look for `var-lib-sev\x2dsigner.mount/stop` |
| `systemd-resolved.service`: `/var/tmp: No such file or directory`, `226/NAMESPACE` | resolved started before the `/var` tmpfs; fixed by the drop-in in `mkosi.extra/usr/lib/systemd/system/systemd-resolved.service.d/` |
| mkosi stops on a missing ESP or bootloader | `mkosi.repart/` deliberately has no ESP (the UKI is booted with `-kernel`). Add `00-esp.conf` with `Type=esp`, `Format=vfat`, `CopyFiles=/efi:/` and `CopyFiles=/boot:/`. The guest never reads it, and the measurement doesn't change. Record the error |
| mkosi: a package is missing from the snapshot | record the name; the tools tree uses only the base profile (`ToolsTreeProfiles=`) |
| QEMU: SNP not supported, `KVM_SEV_INIT2` fails | SNP is off on the host: BIOS settings (1.1), `kvm_amd.sev_snp`, or SNP firmware |
| QEMU complains about `cbitpos` | set `SNP_CBITPOS` to the host's value (CPUID 0x8000001F EBX[5:0]); it doesn't change the measurement |
| no serial output at all | `-bios` isn't the AmdSevX64 build from `make ovmf`, or OVMF refused the UKI (kernel-hashes mismatch) |
| measurement mismatch | check, in order: the OVMF and UKI hashes in the expected JSON, no `-append`, `SNP_VCPUS` and `SNP_VCPU_TYPE`. Then try `SNP_GUEST_FEATURES=0x21 scripts/expected-measurement.sh` (KVM may have added DebugSwap); record which value matched and the QEMU and kernel versions |
| initrd stops before unlock, or `/sysroot` never mounts | verity: `--image` isn't the `dvtee.raw` from the same build as `--uki` |
| `sealing-key failed`, `firmware status 0x16` | `SNP_MIN_TCB` is above the platform's committed TCB |
| `sealing-key failed`, cannot open `/dev/sev-guest` | the `sev-guest` module didn't load; record the dmesg lines |
| `luksFormat failed` | AEAD cipher missing from the initrd (aegis128 modules); record the message |
| `the mapping is not aegis128-random with AEAD integrity` | the `cryptsetup status` output format differs from the script's check; it is printed just above |
| `cannot open the data disk` on a normal boot | measurement, policy, chip or minimum TCB differ from the boot that created the disk |
| `dvtee serving` but attestation returns 500 | configfs-tsm: the sev-guest TSM provider, or the unit's read-only `/sys` view (`ReadWritePaths=` for `/sys/kernel/config/tsm/report`); record the signer's error line |
| dvtee.service fails with `NAMESPACE` / `226` | `/sys/kernel/config/tsm/report` doesn't exist: the `tsm` or `sev-guest` module isn't loaded, or configfs isn't mounted |
| blocks and attestations get 503, `no trusted time` in the serial log | the guest can't reach a Roughtime quorum: no outbound UDP from the guest, or no DNS (`systemd-resolved` and the DHCP-provided resolver); record which servers answered |
| guest powers off after `dvtee-provision` | the provisioning archive was rejected; the reason is in the line before |

