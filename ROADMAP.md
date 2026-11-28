# DVTEE: status and roadmap

Where `dvtee` stands as a Web3Signer-compatible BLS signer for Obol distributed validators,
running in AMD SEV-SNP (later Intel TDX and Arm CCA), and what is left before it can hold real keys.
It was first written in October 2026 and is updated as the work moves.

This repo is published early, before end-to-end testing or hardening, so that others building TEE
signers can compare designs. Nothing here has run on SEV-SNP hardware or been audited. See
[Known gaps](#known-gaps) before drawing conclusions from the code.

## TL;DR

* **The signer (`signer/`, binary `dvtee`) is a small Rust Web3Signer-compatible eth2 signer**
  with:
  * recomputed signing roots for every request type through Gloas, cross-checked against
    go-eth2-client with herumi BLS, the consensus spec tests and Web3Signer's own examples;
  * durable EIP-3076 slashing protection, checked against the EIP-3076 interchange tests;
  * TLS terminated inside the guest, plus optional pinned-cert mTLS;
  * a vendor-neutral attestation endpoint (configfs-tsm) that binds the evidence to the TLS key and the
    BLS key set.
* **The biggest remaining gap is the guest image, not the signer.** The current Alpine image is unsafe
  as built (details below). Replace it with a reproducible mkosi image rather than patching it.
* **It is meant to be one share in a DV cluster, not a solo signer.** The design leans on the cluster
  for key generation (DKG inside the guest), recovery and image upgrades (the other operators rebuild a
  lost share; no key export), and anti-rollback. See
  [Where it fits](#where-it-fits-one-diverse-share-in-a-cluster) and
  [docs/cluster-edits.md](docs/cluster-edits.md).

## Findings

### Guest image tooling (2024 prototype, last touched January 2025)

Good ideas worth keeping:

* UKI boot with `kernel-hashes=on`, so kernel, initramfs and cmdline are measured.
* The dm-verity root hash on the measured cmdline.
* A disk key derived from the SNP measurement.

As built, though, the image does not protect a signer:

| # | Severity | Finding |
|---|----------|---------|
| 1 | Critical | **`/var` and `/home` are plain ext4 with no encryption or integrity** (`install.sh` partitions 3 and 4). The root is read-only, so these are the *only* writable locations. Any key, password or slashing DB would sit in cleartext on host-controlled disk. Only the immutable root, which is public code, is encrypted. That is backwards. |
| 2 | Critical | **The host can get a shell inside the guest.** Accounts are `root:root` and `signer:signer` with `doas nopass`. openssh is installed and port 22 is forwarded. The serial console is on stdio. Every failed initramfs step (`eend`) drops to `/bin/busybox sh`; `rd.shell=0` is not honoured by this init. All of this is part of the *measured* image, so a valid attestation would vouch for an image the host can log into. |
| 3 | Critical | **The first-boot step that seals the disk to the SNP key looks unable to run as written** (not run on hardware). It lives in `runtime/user-data`, but `install.sh` disables cloud-init on the target root. It also writes `/crypto_keyfile.bin` and creates `/tmp/canary` on a root mounted read-only. If it doesn't run, the disk stays unlocked by the literal key `"0\n"`. |
| 4 | High | **Host-writable code runs inside the TEE.** `snpguest` is executed from `/home/signer/.cargo/bin`, which lives on the unauthenticated `/home` partition. |
| 5 | High | **A firmware update bricks the disk.** The key is derived with `--guest_file_select 111111`, which includes TCB version. Any AMD firmware or microcode TCB update changes the key, with no recovery path. |
| 6 | High | **No attestation flow.** Nothing produces or verifies a report for a remote party, and nothing binds a channel key to it. |
| 7 | High | **Not reproducible, so there is no expected measurement to compare against.** OVMF is now built reproducibly from pinned edk2 (`ovmf/`); the old blob is gone. Alpine and kernel 6.11 (EOL) are unpinned, `cargo install snpguest` takes the latest version at build time, and packages are installed with `apk --allow-untrusted`. |
| 8 | Medium | LUKS without integrity (no dm-integrity/AEAD): the host can tamper with or replay ciphertext sectors. There is also no rollback protection for state, which matters for slashing protection. |
| 9 | Low | The `Makefile` `provision-*`/`run-*` targets `cd` on a separate recipe line, so they run from the wrong directory. |

`poc/` runs stock Web3Signer inside an Ubuntu SNP guest that the operator administers over SSH, with
slashing protection off and attestation verification left as a TODO. It demonstrates the
DKG-in-TEE flow but provides no security boundary.

Earlier Obol prototypes (an older copy of `poc/`, and a Rust Web3Signer prototype from 2024) were
reviewed at the same time and are superseded by `signer/`.

## What the signer does now

* **Web3Signer eth2 API.** `POST /api/v1/eth2/sign/{pubkey}`, `GET /api/v1/eth2/publicKeys`,
  `/upcheck` and `/healthcheck`, with text or JSON responses selected by `Accept`.
* **Request types through Gloas.** ATTESTATION, BLOCK_V2 (header), RANDAO_REVEAL,
  AGGREGATION_SLOT, AGGREGATE_AND_PROOF (v1 and V2, phase0 to Gloas), the three sync committee types,
  VOLUNTARY_EXIT (EIP-7044), VALIDATOR_REGISTRATION and DEPOSIT, plus the Gloas types
  PAYLOAD_ATTESTATION_MESSAGE, PROPOSER_PREFERENCES, EXECUTION_PAYLOAD_ENVELOPE (self-built blocks
  only, and only for a block this signer signed) and BUILDER_REQUEST_AUTH. EXECUTION_PAYLOAD_BID is
  refused: it is a builder's message.
* **Fork schedule.** Presets carry each fork's version and epoch, and `--network` also takes a
  standard consensus `config.yaml` (devnets). A request's fork version and schema must match the fork
  at its slot.
* **Never signs a client-provided root.** Each root is recomputed from the typed object, and the domain
  is chosen by request type. A mismatching `signingRoot` is rejected. A signer that blind-signs roots is
  a universal signing oracle, which would defeat the point of putting the key in a TEE. That includes a
  generic "sign this root under this domain" call guarded by a list of forbidden (slashable) domains:
  it still signs deposits, registrations and exits with any contents, and every domain a future fork
  adds. dvtee only signs request types it knows, and refuses the rest.
* **Verified against an independent implementation.** Signing roots and signatures match go-eth2-client
  plus herumi BLS (`tests/vecgen`) byte for byte.
* **Network pinning.** Requests whose `genesis_validators_root` differs from the configured network are
  rejected (mainnet, hoodi, sepolia, or custom).
* **Policy.** Exits are allowed by default; deposits are denied by default.
* **Client roles.** A third `knownClients` column grants each client certificate `duties`, `exit` or
  `deposit`; anything not granted is refused (design choice 9).
* **Cluster lock pinning.** `--cluster-lock` pins the signer to a charon lock (v1.7.0 to v1.11.0) on
  first start. It checks the lock's hashes and aggregate signature and that every loaded key is one of
  its shares, then refuses any other lock. Registrations, proposer preferences and self-built payload
  envelopes must carry the lock's fee recipient. The lock hash is bound into attestation evidence.
* **Slashing protection.** Per-key low watermarks, fsynced before the signature is released. Supports
  EIP-3076 import at startup and `slashing-export`. Passes the EIP-3076 interchange test suite
  (v5.3.0, minimal strategy) in CI.
* **Keystores.** Loads EIP-2335 keystores in charon's `validator_keys/` layout (scrypt and pbkdf2,
  NFKD password processing).
* **TLS.** Rustls TLS inside the guest. The key is generated on first boot into the data directory, and
  client certificates can optionally be pinned in Web3Signer `knownClients` format. Lighthouse and Teku
  both support both.
* **Attestation.** `GET /api/v1/tee/attestation?nonce=` uses configfs-tsm, so the same code serves
  SEV-SNP, TDX and CCA. REPORT_DATA binds the nonce, the TLS certificate and the BLS key set.
* **Offline evidence check.** `dvtee verify-evidence` checks the AMD chain against pinned roots,
  the report signature, the VCEK's TCB and chip id, guest policy, a minimum TCB, the binding and the
  expected measurement.
* **Footprint.** No consensus types library. SSZ merkleization, including the progressive types Gloas
  uses (EIP-7916, EIP-7495), is hand-rolled and checked against the consensus spec tests (v1.7.0-beta.4
  `ssz_static`) and the ssz-specs progressive vectors.

**Not yet verified:** it has not run inside a real SNP guest. The configfs-tsm path and the SNP and TDX
report offsets come from the specs; they have not been exercised on hardware.

## Where it fits: one diverse share in a cluster


Cloud TEE signers, such as [lidofinance/tee-signer](https://github.com/lidofinance/tee-signer) on AWS
Nitro, Azure SEV-SNP and GCP Confidential Space, seal keys with a cloud KMS policy, so the cloud vendor stays in the trust base for the key itself.
DVTEE is chip-specific instead: AMD SEV-SNP, with the chip as the sealing root and attestation
checked against AMD's own certificate chain. It still runs on rented machines, but the provider can stop
it, not unseal it. The two fail in different ways, which is the point of running both in one cluster.

| | Cloud-KMS-sealed TEE signers (typical) | DVTEE (target design) |
|---|---|---|
| Sealing root | Cloud KMS / Key Vault policy | SNP derived key (`MSG_KEY_REQ`) over measurement, policy and a minimum TCB |
| Who else can unseal | With a locked key or release policy (AWS, Azure), not the operator's admins; the cloud's KMS and attestation services stay trusted. GCP's rule can't be locked. | Nobody but AMD firmware; physical DIMM attacks are out of scope |
| Key creation | Often a dealer outside the TEE, then import | Charon DKG pushes the share over attested TLS (plan A), or the guest does DKG's share operations itself so the share never exists outside it (plan B) |
| Recovery | Re-import of shares kept outside the TEE, or a TEE-to-TEE handover | `charon edit recover` (proposed): a threshold of operators rebuilds the lost share inside a new guest |
| Upgrade | New image key policy, then re-import or handover | Recover the share into a guest running the new image; the old guest retires and exports nothing |
| Hosting | AWS Nitro, Azure and GCP confidential VMs | Operator-controlled AMD SEV-SNP hardware first (owned or rented bare metal); cloud SNP guests that reach the chip directly (AWS EC2) as an option |
| Attestation trust | Cloud-signed tokens or cloud PKI | The raw SNP report, checked against AMD's chain |

Cluster shape guidance that follows from this:

* **No 1-of-1.** Any single TEE signer is a single point of failure for liveness and, with a hostile
  host, for safety. Use threshold.
* **Chip-family and vendor diversity.** No chip family, cloud or codebase should hold two shares. If
  another share runs on SNP in a cloud, run that one on Nitro or TDX instead, so one SNP firmware bug
  never hits two shares.
* **Two margins, because there is no backup.**
  * **2t − n ≥ 2 (safety).** Any two quorums share at least two signers, so one duplicated or
    rolled-back share (a clone, a restored disk, an old guest still running after a recover) can't
    complete a slashable pair on its own. Charon's default thresholds meet this from n = 4; 2 of 3
    does not.
  * **n − t ≥ 2 (key survival and liveness).** Losing n − t + 1 signers before a recover loses the
    validator key, because no copy exists outside the guests. With n − t ≥ 2 the cluster survives two
    dead machines, or one mid-upgrade while another fails.
  * Both hold from n = 6 (4 of 6, 5 of 7). A 3-of-4 cluster meets only the first. It is acceptable
    when the withdrawal credentials can trigger an exit from the execution layer (EIP-7002), so losing
    two machines costs an exit and a re-deposit, not the funds.

## Path to production for Obol DVs

### DV-specific design choices

1. **Key shares only enter the guest encrypted to it.**
   * **Plan A: the keymanager API.** `charon dkg --keymanager-address … --keymanager-auth-token …`
     already pushes new shares to a keymanager instead of writing them to disk. dvtee would
     implement the keymanager import endpoint (`POST /eth/v1/keystores`, bearer token as the spec
     requires) on the mTLS listener.
     * Charon would first verify the signer's attestation and pin the TLS certificate bound into it.
       Then the keystore and its password reach only the measured guest.
     * That is a small extension on charon's side, and possibly in the keymanager API, if we want
       the share encrypted to a guest key rather than only protected by TLS.
     * Limit: the share still exists in charon's memory on the DKG host during the ceremony.
   * **Plan B: the guest does DKG's share operations.** Charon runs the ceremony outside; the guest
     deals and combines (design choice 8), so the share is generated inside and never exists outside
     it. The PoC showed a heavier version of this flow, with all of charon inside the guest.
2. **Recover by rebuilding, not by key export.** If a guest is lost (hardware failure, a TCB change
   that alters the sealing key, a VM that lands on a different chip) or has to move to a new image, the
   cluster keeps signing at threshold while a proposed `charon edit recover` has `t` other operators
   rebuild the same share inside a new guest. The lock, public shares and every other operator's share
   stay as they are. A reshare (`recreate-private-keys`, `replace-operator`) remains the tool for when a
   share may have leaked or the operator set changes. Strict sealing is then acceptable: there is no
   export path, so there is none to attack. A new image is admitted only by the operators' threshold
   order, never by a maintainer or vendor key. Design and the requirements for charon:
   [docs/cluster-edits.md](docs/cluster-edits.md).
3. **A compromised node holds only one share.** Below-threshold compromise cannot produce slashable
   signatures. What the TEE adds is protection for the share against a compromised host (theft,
   cloning, using the signer as an oracle), and in-TEE slashing protection.
4. **Proposed: peers attest each other's signers** (needs charon changes). Each charon node fetches
   and verifies its peers' signer evidence at startup and on a timer, and exposes the result as a metric and a cluster health check.
   The cluster then knows how many of its shares are actually TEE-protected. No single-operator
   signer can offer that.
5. **Built: a start floor against rollback.** A TEE cannot stop the host from restoring an old disk
   snapshot, which rolls back slashing watermarks. The signer never signs more than `k` epochs ahead
   of a trusted clock, and after every start it refuses all votes and proposals up to
   `clock_epoch + k + 1`, plus votes with a source before `clock_epoch + k` (surround votes). Anything
   signed before the restart is then below the floor, whatever the disk says. The cost is about three
   epochs of missed duties per restart for one signer (k = 1), which the cluster covers.
   * The trusted clock is a quorum of Roughtime servers with pinned keys (3 of 5 independent operators
     by default). The guest's clock, which the host controls without SecureTSC, only expires a
     reading; it never moves the horizon forward.
   * Signed timestamps from the other signers in the cluster remain an option that needs no outside
     servers.
   * See [State](docs/cluster-edits.md#state-watermarks-rollback-and-power-cycles) and
     [`signer/README.md`](signer/README.md#anti-rollback-start-floor-and-horizon).
6. **Clones are a host capability to design for.** A host can boot two guests from the same image.
   Both pass attestation and, if sealing is to `MEASUREMENT | POLICY`, both derive the same disk key.
   Within one cluster a clone holds the same share, so it cannot reach threshold on its own. It can
   still double-sign with that share; with 2t − n ≥ 2 another honest signer must also sign both
   messages, and its slashing protection refuses.
7. **Settings come from the cluster lock, and change only with a new lock.** (Fee recipient and
   exit role built; runtime deposits still a startup flag.)
   * The fee recipient for builder registrations, Gloas proposer preferences and self-built Gloas
     payloads comes from the cluster lock, which every operator signed. Requests with another one are
     refused. Gas limits are not pinned.
   * The signer pins the first lock it is given and refuses any other afterwards. Changing a fee
     recipient means a new lock, and a new lock means new shares: a reshare into fresh guests. There is
     deliberately no runtime path to change it, so charon's runtime proposer configuration does not
     apply to a pinned signer.
   * **Why the pin, not just the signatures.** The lock's aggregate signature has no proof of
     possession, so a host that controls the lock file could build a fake lock around the signer's real
     shares that still verifies. Checking the lock catches mistakes. The protection against a host is
     the pin on the sealed disk plus the lock hash in the attestation evidence, which peers compare with
     their own lock.
   * Exits are allowed, but only for clients with the exit role (design choice 9). Runtime deposits
     stay off unless enabled at provisioning.
8. **Proposed: charon runs ceremonies; the guest does only what touches a share.** DKG, reshare and
   recover keep their networking and lock handling in charon. The guest checks a ceremony order signed
   by a threshold of operators, then deals, combines, and signs lock hashes, deposits and registrations
   it computes itself from the order's fields. It never signs a caller-supplied hash and never exports
   a share. Design: [docs/cluster-edits.md](docs/cluster-edits.md).

### Phases

9. **Client roles, denied unless granted (built).** Each pinned client certificate carries the
   operations it may request, and anything not listed is refused, including request types added by a
   future fork.
   * The validator client's certificate gets duties: attestations, blocks, aggregation, sync committee,
     RANDAO and, where enabled, registrations and proposer preferences.
   * **Exits need a separate certificate with the exit role**, held by whoever signs exits (charon's
     exit tooling, an operator's admin machine). A stolen validator-client certificate then can't exit
     validators. This follows other TEE signers, which keep exits behind an admin role.
   * Runtime deposits, where enabled at provisioning, get their own role too.
   * Format: an optional third column in the `knownClients` file, e.g. `vc-node0 <sha256> duties` and
     `ops <sha256> exit`. A line without one keeps today's behaviour during the transition.

**Phase 1: a minimal guest that can be trusted (biggest gap)**

* Build the image with **mkosi**: reproducible builds, a UKI, a dm-verity root via systemd-repart, and
  a data partition on LUKS2 with dm-integrity (AEAD). **Written, not yet built or booted** (`image/`,
  first hardware session: [docs/hardware-runbook.md](docs/hardware-runbook.md)).
* No shell, no getty, no sshd and no passwords. The only network listener is dvtee; ceremonies
  reach it through charon on the host. Logs go out over the network or the serial console.
* Pin and build the kernel from source (OVMF: done, see `ovmf/`).
* Publish expected launch measurements computed with `sev-snp-measure`.
* Seal the data key with the SNP derived key using `MEASUREMENT | POLICY` and a pinned **minimum**
  TCB (snpguest `--tcb_version`), not the current TCB. That way firmware updates don't brick the disk
  and downgrades below the minimum can't unseal it. The signer side is done (`dvtee sealing-key`,
  untested on hardware); the image still has to call it from the initrd.
* **Fast restarts.** Once shares live on the sealed disk, the EIP-2335 password layer adds nothing
  against disk theft. Store them in a form that loads without scrypt or PBKDF2, so a restart costs
  seconds instead of a key-derivation pass per key (about 11 s for 8 keys in a debug build today).

**Phase 2: attestation in the operator workflow**

* Add a verifier that checks the AMD chain (ARK → ASK → VCEK from KDS), the report signature, the
  measurement, the policy (debug off, SMT/migration policy) and the binding. Done in
  `dvtee verify-evidence`, offline with pinned AMD roots. It still needs a run against a live
  report, and charon needs a Go equivalent or a way to call it.
* Pin the attested TLS certificate in the validator client's web3signer configuration.
* Have charon verify peers' signer evidence at startup and periodically, and expose it as a metric
  (design choice 4). Ceremonies depend on this too: it is how operators check that a ceremony key really
  belongs to a peer's guest.
* **Cluster edits** ([docs/cluster-edits.md](docs/cluster-edits.md)):
  * specify `recover` and the ceremony order format in distributed-validator-specs, with test vectors;
  * implement `charon edit recover`;
  * add the guest's ceremony operations (deal, combine, complaints, recover steps, tombstone) to
    dvtee's local API;
  * key slashing watermarks by validator, and carry them over on reshare.
* **Client authentication in depth: mTLS and a bearer token.**
  * **Why two secrets.** dvtee pins client certificates, so a public CA failure can't forge a
    client. But a client key can still be weakly generated or leak; in October 2026 a public CA's
    intermediate keys turned out to be derivable from their certificates. A second, independently
    generated secret covers that case.
  * **Where it is required.** The keymanager import endpoint (design choice 1) needs the token
    anyway, because the keymanager API specifies a bearer token.
  * **Public listener.** `--public-listen` serves health and attestation on a second TLS port with
    the same certificate and no client authentication, so peers can fetch evidence while signing
    stays behind mTLS.
  * **mTLS.** Keep pinned client certificates (`--tls-known-clients`) on by default.
  * **Bearer token (built).** `--auth-token-file`, with roles per token like `knownClients`.
    * Require `Authorization: Bearer <token>` on `/api/v1/eth2/*`, compared in constant time.
    * Also accept the token as the password of HTTP Basic auth, because validator clients can only
      put credentials in the URL (`https://x:<token>@signer`).
    * Answer missing credentials with `401` and `WWW-Authenticate: Basic`. Teku only sends Basic
      credentials after that challenge.
    * The public listener is unaffected.
    * Never accept the token in a query string, and never log the `Authorization` header or URL
      userinfo.
  * **Validator client support** (devnet survey, see [`signer/README.md`](signer/README.md#validator-clients)).
    No client has a header option. Lighthouse, Prysm and Nimbus send URL credentials as Basic auth
    on every request; Teku does after a `401` challenge, over HTTPS only. Only Lighthouse and Teku
    support a client certificate. Lodestar supports neither, so a Lodestar signer is protected only
    by network isolation until upstream adds one of them.
  * **Provisioning.** Generate the token in the guest at first start and store it on the sealed disk.
    Hand it out once, over the attested, mTLS-authenticated channel. Rotate it by restarting with a
    new file.

**Phase 3: hardening the state**

* **Anti-rollback for slashing protection** (design choice 5): done with a Roughtime quorum, the
  "never more than `k` epochs ahead" rule and the start floor. Still open: timestamps from the
  cluster's other signers as a second source, and SNP SecureTSC (Genoa and later) to keep signing
  through short Roughtime outages.
* **Rollback after a reshare.** A restored disk can bring back a retired share. Tombstones and the share
  generation must be covered by the same protection as the watermarks.
* **Metrics, off by default.** `--metrics-listen` serves Prometheus metrics: sign latency by request
  kind, rejections, slashing refusals, watermark sync time, and the build commit and measurement.
* **Watermark writes without a journal commit each.** The load test ([docs/load-test.md](docs/load-test.md))
  meets 100 attestations a slot with the full DV duty mix: median 22 ms, every request under 1 s
  (worst 0.99 s). With consolidated (0x02) validators a signer sees about 30 a slot, where p99 was
  25 ms. The tail comes from disk syncs: each watermark is a new file, two fsyncs and a rename, and
  slow ext4 journal commits delay whole bursts, up to 1.9 s at 200 a slot. Without fsync the same box
  signs 6400 attestations a slot with p99 440 ms. Grouping the per-file writes was slower on a quiet
  disk, since concurrent fsyncs already share journal commits. A store that overwrites fixed records
  in a preallocated file with `fdatasync` (0.7 ms instead of 9 ms, no journal commit) is the
  candidate. Rerun the load test on SNP hardware and its real data disk first.
* Fuzzing of the request parsers.

**Phase 4: Intel and Arm**

* The signer already uses configfs-tsm.
* The image needs TDX-capable OVMF/TDVF builds and RTMR-based measurement.
* **TDX has no sealing-key primitive.** Its data key must come from a key broker (attested KMS), or
  the TD must get its share again after every restart, by DKG or recover. Recover makes the second
  option viable without new infrastructure, at the cost of a ceremony per restart.

### Hosting

**Decision: operator-controlled AMD SEV-SNP hardware first, cloud SNP as an option.** The primary
target is EPYC (Milan or later) servers the operator owns or rents as bare metal, with our own pinned
OVMF build. Cloud SNP guests that reach the chip directly (AWS EC2 SNP instances) are a secondary
target. The aim is to take every third party out of key custody, not to be cloud-agnostic.

* **Why chip-specific.** Only SNP gives the guest a sealing key derived by the chip (`MSG_KEY_REQ`),
  so no KMS policy, IAM role or support process can release the key. Intel TDX has no equivalent,
  so a TDX signer needs an external key broker, which brings the cloud back into key custody.
* **Platforms that don't fit.** Azure confidential VMs run a paravisor between the guest and the
  chip, and Nitro Enclaves are not SNP. Both put the cloud back in the attestation or sealing path.
* **What the cloud still controls.** It supplies the launch firmware on EC2, so we pin and verify a
  published measurement rather than our own OVMF build (`ovmf/` stays for VPS and bare-metal hosts).
  It can stop the VM, roll back its disk, or attack the hardware physically. SEV-SNP's threat model
  leaves physical memory attacks (BadRAM, Battering RAM) out of scope.
* **Host moves lose the sealed share.** A chip-derived key is unique to one physical CPU, so a
  stop/start or host migration lands the VM on a chip that can't unseal its data. In a DV cluster
  that is a lost node: the cluster keeps signing at threshold, and a recover rebuilds the share in a new
  guest. Plan operations around it, and size clusters with n − t ≥ 2.
* **To verify on real instances:** that EC2 SNP guests get `/dev/sev-guest` derived keys and the raw
  report, and what the launch measurement covers there (firmware only, or kernel, initramfs and
  command line too).

## Known gaps

The honest state today. None of these are hidden; most are planned in the phases above.

| Area | State |
|---|---|
| Hardware | Never run in a real SNP guest. configfs-tsm reading and the SNP/TDX report offsets come from the specs. The SNP derived-key ioctl behind `sealing-key` is pinned to the kernel UAPI header by tests but has not been run. Everything else can be developed on any Linux machine with the `insecure-dev` platform (see [`signer/README.md`](signer/README.md)). |
| End-to-end | `e2e/devnet/` runs a Kurtosis devnet with a 3-of-4 charon cluster where Lighthouse, Teku, Lodestar and Prysm each sign through their own dvtee (insecure-dev). Over two runs: charon accepted every partial signature, every duty type including aggregates reached the chain, DV duties kept working with one node down, and slashing protection held across signer restarts. Runs are manual (about 4 GB of RAM, 15–40 minutes), not in CI. Only the insecure-dev platform has been tested. `e2e/simnet.sh` is a lighter local smoke test on charon's beacon mock. |
| Attestation verification | `verify-evidence` verifies SNP evidence offline: the AMD chain with the Milan, Genoa and Turin ARKs pinned, the report signature, the VCEK's TCB and chip id, guest policy and VMPL, the binding and the measurement. It is tested with a real Milan report and a real Turin VCEK, but not yet with a live report from our guest. Not checked: AMD's CRL, the configfs-tsm `auxblob` certificate table on a real host, and TDX quote signatures. |
| Minimum TCB | `sealing-key` mixes a pinned minimum TCB into the SNP key. `verify-evidence --min-tcb` takes the same value and checks the reported and committed TCB against it, component by component. Neither has run on hardware. |
| Guest image | The 2024 Alpine image is unsafe for keys (see Findings). The mkosi image (`image/`) builds, and builds from two separate checkouts are byte-identical; it has not yet booted on SNP hardware. Keys reach it through a temporary, host-readable first-boot disk. |
| Anti-rollback | Start floor and horizon from a Roughtime quorum (design choice 5), on by default for public networks. It covers slashing watermarks only, not tombstones or share generations (cluster edits are not built). It depends on outbound UDP to the Roughtime servers, and three of the five defaults must answer. Without a quorum, blocks and attestations stop. Not yet run in the e2e devnet. |
| Cluster edits | Not implemented. Recover, the reshare family with guests, ceremony orders and tombstones are designed in [docs/cluster-edits.md](docs/cluster-edits.md). Watermarks are stored per share pubkey, so a reshare would start them empty until they are keyed by validator. |
| Forks | Gloas types implemented against consensus-specs v1.7.0-beta.4 and remote-signing-api v1.4.0, checked against the spec tests, go-eth2-client and Web3Signer's examples, and run on a Gloas devnet: Lighthouse, Teku, Lodestar and Prysm each signed every Gloas kind they use through dvtee in a charon cluster, with no rejections, and every PTC vote was included. Gloas is still changing upstream, so each spec release needs re-checking. |
| Exits | `VOLUNTARY_EXIT` needs a client certificate or token with the `exit` role, and is not rate limited. In a DV each signer holds one share, so an exit needs a threshold of operators to sign. A `knownClients` line without roles still gets `exit`, for compatibility. A signer with neither mTLS nor tokens checks no roles. Exits authorised by a party other than the operators are an open design item. |
| Operations | No metrics (planned, opt-in) or request-parser fuzzing. |
| Load | Measured on a dev box only, not in an SNP guest ([docs/load-test.md](docs/load-test.md)): 100 attestations a slot plus the rest of the DV duty mix complete within 1 s, at a 22 ms median. Disk syncs set the tail (bursts up to 1.9 s at 200 a slot on a consumer NVMe), not signing. |
| Client auth | Pinned-cert mTLS with roles on the signing listener, bearer tokens with roles (`--auth-token-file`, also accepted as the Basic password from a URL), and an optional public listener for health and evidence. Lodestar can send neither a client certificate nor URL credentials, so a Lodestar signer is protected only by network isolation. Tokens are still provisioned as a file; generating one in the guest and handing it out over the attested channel is planned. |
| Key import | Keystores and password files are read from a directory. Encrypted import over the keymanager API, or DKG inside the guest, is planned (design choice 1). |
| Pinned settings | Fee recipients are pinned from the cluster lock (`--cluster-lock`), and the lock itself is pinned on first start. Without a lock (solo use), fee recipients are not checked. Pre-Gloas block fee recipients can't be checked (headers only). Deposits remain a startup flag. |
| Review | Unaudited, with no external review yet. |
