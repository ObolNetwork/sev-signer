# Threat model

What DVTEE protects, what it trusts, and what it doesn't try to stop. The status column says
whether a protection is built or planned; [ROADMAP.md](../ROADMAP.md#known-gaps) has the details.

## Deployment assumed

- One dvtee guest per operator, each holding that operator's key shares of a charon distributed
  validator (DV) with threshold `t` of `n`.
- The guest runs on AMD SEV-SNP hardware the operator owns or rents as bare metal. A cloud SNP guest
  that reaches the chip directly is an option.
- The operator's host runs charon, the beacon node and the validator client, outside the guest.
- Recommended shapes: 4 of 6 or 5 of 7 (`2t − n ≥ 2` and `n − t ≥ 2`). Use 3 of 4 when the withdrawal
  credentials can trigger an exit (EIP-7002).

## Assets

1. **Key shares.** No share should ever exist outside a guest in plaintext.
2. **Slashing safety.** No set of signers may produce two slashable messages for one validator.
3. **Settings:** the fee recipient, who may exit, and runtime deposits.
4. **Liveness:** signing duties on time. This is the lowest priority. A compromised operator can always
   stop its own signer.

## What is trusted

| Component | Why it is trusted | Notes |
|---|---|---|
| AMD SEV-SNP silicon, PSP firmware and microcode (closed source) | Memory encryption, the launch measurement, the attestation report, and the chip-derived sealing key | A minimum TCB is pinned in the sealing key and checked by the verifier. Physical attacks on memory are out of scope (below). |
| AMD's key infrastructure (ARK, ASK, VCEK) | Signs the attestation report's chain | Root certificates pinned by fingerprint. |
| The measured guest image: OVMF, kernel, initrd, command line, dm-verity root, dvtee | Everything that runs in the guest | Reproducible builds, so anyone can recompute the measurement from source. |
| Pinned crypto dependencies (blst, rustls, ring, RustCrypto) | Signing, TLS, hashing | Exact versions, `cargo deny`. |
| A threshold of the cluster's operators | Admitting a new image, recovering a share, changing settings | The same bar as the validator key in any DV. |
| A quorum of Roughtime servers | The start floor's notion of "now" | Fewer than the quorum may lie. If they don't answer, signing stops; nothing unsafe is signed. |

**Not trusted:**
- the host OS and hypervisor;
- the host's disk and network;
- the host's clock;
- charon;
- the validator client;
- the beacon node;
- the DVTEE maintainers, after a release.

A maintainer key cannot admit an image or move a share.

## Adversaries

| Adversary | Can | Cannot | Status |
|---|---|---|---|
| **Root on one operator's host** | Stop, pause or slow the guest; clone it; roll back or drop writes to its disk; feed it any request through the validator client's credentials; hand it a wrong cluster lock before its first start | Read a share or the TLS key; get a signature over a root it chose (the guest computes every root from typed fields); get a slashable message from this guest past its watermarks; complete a slashable pair alone (needs `2t − n` shares); change the pinned fee recipient or lock; exit without the exit-role credential | Built, except where the rows below say planned |
| … rolling the disk back to an old snapshot | Restart the guest with older watermarks | Re-sign epochs before the restart: the start floor refuses everything up to the trusted epoch plus a margin | Start floor: built with this release series; peer-witness time: planned |
| … cloning the guest | Run two copies of one share | Complete a slashable pair: two copies are one index, and with `2t − n ≥ 2` another honest signer must sign both messages | By cluster shape |
| … swapping the cluster lock before first start | Pin a fake lock built around the real shares (the lock's aggregate signature has no proof of possession) | Hide it: the pinned lock hash is in the attestation evidence, and peers compare it with their own lock | Built; peers checking it automatically is planned (charon) |
| **A stolen validator-client credential** (certificate or token) | Request duties | Exit or deposit (separate roles); sign anything slashable past the watermarks | Built |
| **Root on `t − 1` hosts** | All of the above on each | Reach threshold; start a ceremony | By threshold |
| **Root on `t` hosts** | Authorise a ceremony, including a recover into a key they control | — this is threshold compromise | Raising this bar with in-guest attestation checks is an open design question |
| **A malicious image** | Anything inside its own guest | Get a share, unless `t` operators signed an order admitting its measurement | Recover and ceremony orders: planned |
| **The cloud or hosting provider** | Everything root on the host can; stop the machine | Unseal the disk (the key is derived by the chip, not by a cloud KMS) | Built (signer side); first hardware run pending |
| **Network attacker** | Delay or block traffic | Impersonate the signer (TLS key bound into attestation) or a client (pinned certificates, tokens) | Built |

## Out of scope

- **Physical attacks on memory and chips:** interposers, DRAM aliasing, fault injection, and chip
  decapping. SEV-SNP doesn't claim to stop them. Rented machines should be in a provider's locked
  facility, and the cluster shape keeps one compromised machine below threshold.
- **AMD firmware or silicon bugs.** Diversity across chip families and vendors in one cluster limits the
  damage. No chip family should hold two shares.
- **Side channels between guests on one host,** beyond what SEV-SNP and the pinned minimum TCB give.
- **Requests that aren't slashable but are harmful:** for example, voting for an attacker-chosen head.
  Any signer can be asked for these; the cluster's consensus on duty data limits them in a DV.
- **Solo use.** One guest is a single point of failure. A solo operator also needs a key backup outside
  the TEE, which the TEE can't protect.

## Known limits

- Pre-Gloas blocks are signed as headers, so their fee recipient can't be checked. From Gloas, the
  self-built payload's fee recipient is checked.
- A signer without mTLS or tokens checks no client roles. Lodestar supports neither, so it relies on
  network isolation.
- The trusted clock comes from servers outside the cluster until peer timestamps exist.
- Nothing has been audited.
