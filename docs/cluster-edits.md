# Cluster edits with TEE signers

How a charon cluster whose key shares live in dvtee guests recovers a lost signer, moves a signer
to a new image, and changes its operator set, without any share leaving a TEE in plaintext.

Status: design. Nothing here is implemented yet. It is written against charon's existing edit
protocols (`charon edit …`) and the cluster-edit spec in
[distributed-validator-specs](https://github.com/ObolNetwork/distributed-validator-specs/blob/main/docs/dv-spec/dkg-cluster-edits.md).

## Principles

1. **No key export.** A share is never exported, encrypted or not. It enters a guest by DKG, reshare or
   recovery, and it dies with the guest. There is no backup of a share anywhere.
2. **Humans decide, the TEE enforces.** Operators decide what a ceremony does, by signing it with their
   charon identity (ENR) keys. A guest checks that a threshold of the operators in its cluster lock signed
   it, and computes everything that touches its share itself. It does not judge whether a destination is
   trustworthy beyond what the signed order says.
3. **Charon runs the ceremony.** Networking, sync, retries and the lock file stay in charon on the host.
   The guest exposes a few ceremony operations on its local API and never listens to peers directly.
   Charon passes it opaque, encrypted blobs.
4. **The cluster is the recovery mechanism.** A lost guest is replaced by the other operators, not
   restored from a copy.

## What a share is used for in a ceremony

| Operation | Uses the share? | Where it runs |
|---|---|---|
| Sync, broadcast, retries, timeouts | no | charon |
| Build the new cluster lock | no | charon |
| **Deal**: evaluate a polynomial whose constant term is (a multiple of) the share, encrypt the pieces | yes | guest |
| **Combine** received pieces into a new share and check it against public commitments | yes, the new share | guest |
| **Answer complaints** (reveal a disputed piece) | yes | guest, with the limits below |
| **Sign the new lock hash** | yes | guest, which hashes the lock itself from its fields |
| **Sign deposit data and builder registrations** for new validators | yes | guest, from the order's fields |
| Node (ENR) signatures | no | charon |

A guest never signs a caller-supplied 32-byte value. Charon's lock-hash signature has no domain, so an
endpoint that accepted a hash would sign any signing root, including a slashable one. The guest builds the
lock from its fields and hashes it itself, and the same rule holds for deposits and registrations.

## Ceremony orders

A ceremony starts from an **order**, signed by operator ENR keys:

```
order = {
  kind:            recover | reshare | add-operators | remove-operators | replace-operator | add-validators
  lock_hash:       hash of the current cluster lock
  run_id:          random 32 bytes
  not_after:       unix time; the guest refuses the order afterwards
  participants:    [{ share_index, enr, ceremony_key, measurement? }]
  target:          kind-specific: the index to recover, the new threshold, the operators added or removed,
                   or for add-validators the validator count, withdrawal addresses and fee recipients
}
```

- **Signatures.** A guest acts on an order only if at least `t` distinct operators of its current lock
  signed it, where `t` is the lock's threshold. Each operator's charon signs after its human runs the
  command, so a signature is that operator's consent.
- **What the guest checks.** The lock hash matches the lock it was provisioned with, its own share index
  is a participant, `run_id` is new to it, `not_after` is in the future, and the kind-specific rules below.
- **New measurements.** An order that hands a share to a guest (recover, or a new participant in a
  reshare) names the measurement that guest must have. The operators approve it, nobody else: no
  maintainer, vendor or staking protocol holds a key that can admit an image. Signed, reproducible
  releases help each operator decide what to sign (rebuild, compare the measurement, then sign), but
  they gate nothing inside the guest. A new measurement takes effect only after a delay from when
  the order reached `t` signatures, measured on the guest's trusted clock, so other operators can
  object (by withholding their part of the ceremony) before any piece moves. An order signed by all `n`
  operators may skip the delay.
- **Ceremony keys.** Every participant that holds a share in a guest has a per-ceremony encryption key
  generated inside the guest (`ceremony_key`). Pieces are encrypted to these keys with HPKE (RFC 9180),
  with the order hash, sender and recipient as associated data.
- **Ceremony key binding.** A guest's ceremony key is in its attestation report (REPORT_DATA), next to the
  TLS key. Each operator's charon fetches the other participants' evidence, checks it against the
  measurement the order names for them, and refuses to sign the order otherwise.
  - Without this check, a rooted host could swap its own guest's ceremony key for one it controls, sign
    that with its own ENR key, and receive its guest's new share in plaintext. One host's ENR key is
    enough for that, so a threshold of signatures doesn't prevent it. With the check, a swapped key fails
    every honest peer's verification.
  - This needs the attestation verifier of Phase 2 in charon, and is the same check as design choice 4
    (peers attest each other's signers).

## Recover: rebuild one lost share

`charon edit recover` (new) gives a fresh guest the share at index `r` of an existing cluster. The
polynomial, the public shares, the validator keys and the lock are unchanged. Use it for:

- a dead guest or machine, or one that moved to another chip and can no longer unseal its disk;
- **moving a signer to a new image**, e.g. a dvtee release for a new fork. A new image has a new
  measurement and so a new sealing key; it cannot open the old disk, and the old guest exports nothing;
- a lost disk on a non-TEE node (charon can run the same protocol with keystores).

### Protocol

This is a repairable threshold scheme (Laing and Stinson, *A survey and refinement of repairable
threshold schemes*, 2017; implemented as `repairable` in the ZF FROST crates). Helpers `H`, with
`|H| >= t` and `r` not in `H`. All arithmetic is in the BLS12-381 scalar field.

1. **Order.** Kind `recover`, target `r`, helpers `H`, the target's ceremony key and expected measurement.
   Signed by at least `t` operators.
2. **Helper step 1** (each helper `i`, in its guest): compute the Lagrange coefficient `ζ_i` of `i` over
   `H` evaluated at `r`, and `δ_i = ζ_i · s_i`. Split `δ_i` into `|H|` random scalars `δ_i,j` that sum to
   `δ_i`, and send each `δ_i,j` encrypted to helper `j`'s ceremony key.
3. **Helper step 2** (each helper `j`): `σ_j = Σ_i δ_i,j`, encrypted to the target's ceremony key.
4. **Target** (in the new guest): `s_r = Σ_j σ_j`. Check `s_r · G` equals public share `r` in the lock for
   every validator, then seal the shares. A wrong or missing piece fails this check, so a cheating helper
   can stop a recovery but not plant a bad share.

One validator or a whole cluster is the same protocol, run per validator in one batch.

**What each party learns.** The target learns `s_r` and nothing else. A helper sees only uniformly random
pieces and sums. The scheme gives up `s_r` by design, which is why the order must be authorised and
bound to an attested target key.

### Slashing safety

- **The old copy of share `r` may still exist** (a box that comes back, a restored disk, an old image left
  running). Two copies of index `r` don't add signing power: a threshold needs `t` distinct indices.
  Two conflicting messages need `2t - n` common indices, so with **`2t - n >= 2`** at least one honest
  index other than `r` must sign both, and its slashing protection refuses. Charon's default thresholds
  meet this for `n >= 4` (3 of 4, 4 of 6, 5 of 7). A 2-of-3 cluster does not: recover it only when the
  old copy is known to be dead or retired.
- **Watermarks travel with the pieces.** Each helper adds its own slashing watermarks for the validators
  to its step-2 message. The target starts from the highest of each, so a lying helper can only make it
  refuse duties, never sign below what the cluster signed.
- **Start floor.** The target refuses votes and proposals up to a floor epoch derived from trusted time
  (see [State](#state-watermarks-rollback-and-power-cycles)), as after any restart.
- **Retire before switching.** For an image move, retire the old guest first (below), then recover, then
  point the validator client at the new guest. The cluster signs at threshold meanwhile.

### Compared with a reshare

| | Recover | Reshare (`replace-operator`, `recreate-private-keys`) |
|---|---|---|
| Changes | one share, in one new guest | every share, in every guest |
| Lock and public shares | unchanged | new |
| Other operators | stay up, keep their shares and watermarks | all switch to new shares at once |
| Revokes old shares | **no** | yes (all of them) |
| Online during the ceremony | target plus `t` helpers | every remaining operator |
| New cryptography to audit | small: Lagrange, sums, one public-share check | none new in charon, but the guest needs deal, combine and complaint handling |
| Use when | a guest is lost or replaced, an image changes | a share may have leaked, or the operator set changes |

Recover is the routine tool. A reshare is for when an old share must stop being useful, or the set of
operators changes. If an operator also lost its ENR key, the lock has to change, so that is
`replace-operator`.

### Why not an attested handover first

A handover has the old guest check the new guest's report and pass it the share and its slashing
history directly. It keeps exact history and needs no other operator online, which suits a signer run
by a single operator. It is not the primary path here:

- It needs the old guest alive. Dead hardware, a chip move or a TCB change leave nothing to hand over
  from, so recover is needed anyway, and an upgrade path that differs from the recovery path doubles
  what must be built and audited.
- It gives every guest an export operation for its whole life, guarded only by an in-guest measurement
  policy and attestation verifier. Recover's helper step only ever releases random pieces.
- In a cluster the other operators are online for a fork upgrade anyway.

If a handover is added later, it should require the same threshold-signed order as recover.

## The reshare family with TEEs

Charon's four edit protocols (reshare, add, remove and replace operators) run a Pedersen reshare over
the same validator keys and produce a new lock. With guests:

- **Deal and combine in the guest.** The guest of each old participant deals; the guest of each new
  participant combines. Charon carries the encrypted bundles.
- **Thresholds.** The guest enforces `ceil(2n'/3) <= t' < n'` for the new cluster itself, as charon does,
  because `t' = 1` would hand every recipient every dealer's share.
- **Complaints.** Kyber's justification step reveals a disputed piece in plaintext. A guest reveals only
  in reply to a complaint signed with an order participant's ceremony key, only the piece for that
  participant's index, and aborts if more than `n' - t'` participants complain. A rooted host can then
  only make its own index's pieces public, which it was about to receive anyway.
- **Watermarks carry over locally.** dvtee stores watermarks per share pubkey today, so new shares
  would start empty. The guest copies each validator's watermark from the old share to the new share as
  part of the combine step. Newly added operators start from the start floor. Charon should also refuse
  duties for 2 epochs after it loads a new lock.
- **Departing operators retire.** A guest whose operator is removed or replaced writes a tombstone when
  the ceremony finalises and never signs again.

## Add validators and deposits

New validators need fresh keys, which is a DKG, not an edit of existing shares:

- **DKG in the guest** (plan B in the roadmap) or **charon pushes shares over attested TLS** (plan A).
- **Deposits** are signed only inside an add-validators ceremony, with withdrawal credentials and amounts
  from the order. A free-standing `DEPOSIT` request is refused unless runtime deposits were enabled at
  provisioning (below).

## Provisioning-time settings

Some behaviour is useful to some clusters and dangerous to others. It is chosen once, when the guest is
provisioned, stored on the sealed disk, and bound into the attestation evidence so peers and verifiers
can see it:

- **Fee recipient: from the cluster lock, and never changed at runtime** (built: `--cluster-lock`). The
  signer pins the lock and refuses registrations, proposer preferences and self-built payloads with
  another fee recipient. A different fee recipient means a new lock, and a new lock means new shares: a
  reshare into fresh guests. Charon's runtime proposer configuration does not apply to a pinned signer.
- **Runtime deposits:** off by default. They are needed where the depositor isn't known at key
  generation.
- **Voluntary exits:** on, for clients with the exit role only (built; ROADMAP design choice 9).

Turning runtime deposits on later takes a ceremony order of kind `settings`, signed by a threshold of
operators. A loosening change takes effect only after a delay, so operators can notice it. A tightening
one takes effect at once.

## State: watermarks, rollback and power cycles

- **The data disk is ordinary writable storage.** The measured image is the read-only, dm-verity root.
  The data disk (shares, watermarks, settings) is a LUKS2 volume unlocked with the sealing key. Writing
  new data to it, such as a watermark or a new share, doesn't change the measurement or the sealing key.
  LUKS2 with dm-integrity (AEAD) makes tampered sectors fail to read.
- **Power cycles.** Every signature's watermark is written and fsynced before the signature is
  released, so an honest power cut loses nothing that was signed.
- **Rollback.** The host can restore an older copy of the whole disk, or drop writes. The disk still
  opens, with older watermarks. Integrity checks don't catch this; only something outside the disk can.
- **Start floor, with trusted time** (the approach tee-signer uses). The guest refuses to sign more than
  `k` epochs ahead of its trusted clock. After any start it also refuses every vote with a target, and
  every proposal, up to `clock_epoch + k + 1`. Anything it could have signed before the restart is below
  that floor, so an old watermark can't lead to a double vote. The cost is about three epochs of missed
  duties per restart for this one signer, which the cluster covers.
  - Trusted time: a quorum of Roughtime servers with pinned keys, over the host's network, which the
    host can delay but not forge (built, see [`signer/README.md`](../signer/README.md#anti-rollback-start-floor-and-horizon)).
    A delayed answer only makes the floor higher. Signed timestamps from the other signers in the
    cluster are an alternative that needs no outside servers.
  - The floor also refuses votes whose source is before `clock_epoch + k`, so a restored watermark
    can't let a new vote surround an old one.
- **Reshare and rollback together.** tee-signer's documentation points out the dangerous case: after a
  reshare that retires old shares, a guest whose disk is rolled back to its old share brings that share
  back, and an attacker holding `t - 1` other old shares completes a signature. The tombstone and the
  share generation number must therefore be part of what rollback protection covers, not only the
  watermarks.

## Requirements for `charon edit recover`

Recover is the planned path for both a dead machine and an image upgrade, such as a new dvtee
release for a hard fork. The signer side is small. Most of the work is in charon and the specs. This
list collects what each side needs, for whoever designs and builds it.

**Specs (distributed-validator-specs)**
- The order format above, its canonical encoding and hash, and how operators sign it (ENR keys, as for
  lock node signatures).
- The recover protocol, with test vectors: Lagrange coefficients over `H` at `r`, the split of `δ_i`, the
  sums, the public-share check, and failure cases (missing or wrong piece, `r` in `H`, `|H| < t`,
  duplicate indices).
- The HPKE suite and associated data, and the message formats between helpers and the target.

**charon**
- `charon edit recover`: create an order (target index, helpers, the target's ceremony key and
  measurement), collect operator signatures, run the two helper rounds over the existing p2p
  transport, deliver the target's pieces, and report success only after the target's public-share check.
- Peer attestation (design choice 4): fetch each participant's evidence, check the AMD chain, the
  measurement named in the order, and the ceremony key in REPORT_DATA, and refuse to sign otherwise.
- Nothing in charon ever sees a share or a piece in plaintext. Pieces are opaque, encrypted blobs between
  guests.
- Works with keystores too, so non-TEE nodes can recover a lost disk the same way.
- A runbook for a fork upgrade: every operator moves to the new image one recover at a time (or one batch
  with all new guests as targets), keeping the cluster at threshold. With `n - t = 1` (3 of 4), only
  one guest may be down at a time.

**dvtee (guest)**
- A ceremony API on its own listener, behind its own client role (`ceremony`), for charon only.
- Check the order: `t` distinct operator signatures against the pinned lock, own index, fresh `run_id`,
  `not_after`, and the delay for a new measurement on trusted time.
- A per-ceremony key generated in the guest and bound into REPORT_DATA.
- Helper steps 1 and 2, target combine and public-share check, and sealing of the new shares.
- Carry slashing watermarks in the step-2 messages and start from the highest. This needs watermarks
  keyed by validator, not by share pubkey (a recovered share has the same pubkey, a reshared one does
  not).
- Apply the start floor after a recover, as after any start.
- Retire: a tombstone for the old guest when it is still reachable, covered by the same rollback
  protection as the watermarks.

**Open questions for the design**
- Do helper guests also verify the target's attestation themselves, or rely on charon's check? Doing it
  in the guest raises the bar from `t` compromised hosts to `t` compromised hosts plus a forged report,
  at the cost of an attestation verifier inside the guest.
- How long is the measurement delay, and does it apply to recovery onto the same measurement (a dead
  machine) or only to a new one?

## What each attacker can do

| Attacker | Can | Cannot |
|---|---|---|
| Root on one operator's host | Stop or slow its guest, roll back its disk, clone it, refuse to take part in ceremonies | Get a share out of the guest; start a ceremony (needs `t` signatures); swap its guest's ceremony key unnoticed (peers check attestation); make its guest sign a raw hash |
| Root on `t - 1` hosts | All of the above on each | Reach threshold; start a ceremony |
| Root on `t` hosts | Authorise any ceremony, including a recover into a key they hold | — this is threshold compromise, the same bar as for the validator key in any DV. Having the helper guests verify the target's attestation themselves would raise it, at the cost of an attestation verifier inside the guest. |

## Open items

1. **Exits authorised by a party other than the operators.** Some staking protocols decide when a
   validator exits, independently of its operators. Supporting that needs an exit authorisation the guest
   checks (for example a signed request from that protocol's exit mechanism), separate from operator
   orders. Not designed yet.
2. **A second trusted time source** for the start floor: peer timestamps, next to Roughtime.
3. **Peer attestation in charon** (design choice 4), which the ceremony key binding depends on.
4. **Spec and vectors** in distributed-validator-specs for `recover`, the order format, and reshare test
   vectors, which don't exist today.
5. **A hostile-host test suite**: fake recipients, `t' = 1`, forged complaints, raw hashes, replayed run
   IDs, swapped ceremony keys, a rolled-back disk after a reshare.
6. **A formal model** of the authorisation and slashing rules.
