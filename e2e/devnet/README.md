# e2e/devnet: dvtee behind four validator clients on a Kurtosis devnet

This is a 3-of-4 charon distributed validator on a real local chain, where every operator signs through
its own dvtee and runs a different VC. Unlike `e2e/simnet.sh`, which runs against charon's beacon
mock, the chain here is real: blocks, attestations and aggregates have to be valid and get included. This
checks VC wire-format compatibility (for example the v1 `AGGREGATE_AND_PROOF` type that Lighthouse and
Teku send after Electra), and checks that charon accepts every partial signature dvtee produces.

```
Kurtosis enclave: geth + Lighthouse BN, plus a Lighthouse VC with genesis keys 0..55
relay ─┬─ pod0: charon0 + dvtee0 + Lighthouse VC  (mTLS)
       ├─ pod1: charon1 + dvtee1 + Teku VC        (mTLS)
       ├─ pod2: charon2 + dvtee2 + Lodestar VC    (server TLS only)
       └─ pod3: charon3 + dvtee3 + Prysm VC       (server TLS only)
```

- **Chain:** mainnet preset, 12 s slots, Electra and Fulu at genesis, and 64 genesis validators. Gloas
  is not scheduled unless `GLOAS_EPOCH` is set (see [Gloas](#gloas)).
- **DV keys:** genesis keys 56–63, derived from the genesis mnemonic and split 3-of-4. No Kurtosis VC
  holds them.
- **Pods:** each pod's containers share one network namespace, so the VC reaches charon at
  `127.0.0.1:3600` and dvtee at `https://127.0.0.1:9000`. Those addresses match the signer's
  self-signed certificate SANs.
- **TLS:** Lodestar and Prysm have no client-certificate option, so signers 2 and 3 run without
  `--tls-known-clients`. They trust the signer certificate through `NODE_EXTRA_CA_CERTS` and
  `SSL_CERT_FILE` respectively.
- **Nimbus is not included.** It cannot reach a signer with a self-signed certificate: it ignores IP SANs
  and has no CA option.

## Requirements

- Linux with Docker, and the user in the `docker` group.
- [Kurtosis CLI](https://docs.kurtosis.com/install) **1.22.2** (tested), with access to GitHub to fetch
  `github.com/ObolNetwork/ethereum-package@6.1.0-obol.6`.
- charon with `--testnet-capella-hard-fork`. It was tested with main `89e4b00` built from source.
- dvtee built with `cargo build --locked --features insecure-dev`.
- About 4 GB of RAM (measured peak 3.7 GiB, of which 1.1 GiB is Kurtosis's own containers) and about 4 GB
  of images. The images, pulled on first use, are:
  - `sigp/lighthouse:v8.3.3`, `consensys/teku:26.10.3`, `chainsafe/lodestar:v1.50.1`,
    `offchainlabs/prysm-validator:v7.3.1`;
  - `ethereum/client-go:v1.17.10`, `protolambda/eth2-val-tools:latest`;
  - the Kurtosis engine and its supporting images.

## Run

```sh
CHARON=~/charon/charon DVTEE=signer/target/debug/dvtee e2e/devnet/devnet.sh
```

`all` (the default) brings everything up, runs `SLOTS` slots (default 160, 5 epochs), prints a summary,
runs the checks below, then tears everything down. That takes about 40 minutes (`SLOTS=64` takes
about 14). State and logs go to `WORKDIR` (default `./devnet-work`, gitignored), and `logs/` keeps
every container's log after `down`. `WORKDIR` holds the DV key shares and client keys of a throwaway
devnet; delete it when done.

To keep the devnet up while you investigate, run the steps one at a time:
`up`, `keys`, `cluster`, `pods`, `wait`, `summary`, `checks` and `down`.

| Variable | Default | |
|---|---|---|
| `KURTOSIS` | `kurtosis` | CLI path |
| `ETH_PKG` | `github.com/ObolNetwork/ethereum-package@6.1.0-obol.6` | or a local checkout |
| `ENCLAVE` | `dvtee-devnet` | enclave name, also the prefix of the harness containers |
| `WORKDIR` | `./devnet-work` | |
| `SLOTS` | `160` | slots for `wait` |
| `CHARON_DEBUG_NODES` | none | e.g. `1` to run charon1 at debug level |
| `GLOAS_EPOCH` | `18446744073709551615` (not scheduled) | Gloas fork epoch, written into the enclave's `kurtosis-args.yaml` |
| `EL_IMAGE`, `CL_IMAGE` | from `kurtosis-args.yaml` | Kurtosis geth, and Lighthouse BN and VC images |
| `LIGHTHOUSE`, `TEKU`, `LODESTAR`, `PRYSM` | the versions above | DV validator client images |
| `SIGNER3_REMOTE`, `SIGNER3_CERT`, `SIGNER3_LOG` | none | node3's signer runs elsewhere, e.g. in an SEV-SNP guest; see below |

Each dvtee reads the devnet's fork schedule from the genesis `config.yaml`. It is started with
`--network /genesis/config.yaml --genesis-validators-root <gvr>`. `up` checks that the config's
`GLOAS_FORK_EPOCH` equals `GLOAS_EPOCH`.

## A remote signer for node3 (SEV-SNP guest)

With `SIGNER3_REMOTE=<host>:<port>`, pod3 gets no local dvtee. A `socat` forwarder in the pod
listens on `127.0.0.1:9000` and passes the TCP stream to that address, so Prysm is configured as usual
and TLS still terminates inside the remote signer. `SIGNER3_CERT` is that signer's certificate, taken
from its attestation evidence; it replaces `signer-data/tls/cert.pem` for Prysm. `SIGNER3_LOG`, if set,
is read for node3's counts in `summary` (for a guest, its serial log). `checks` only touch signer0.
The full procedure is in [docs/hardware-runbook.md](../../docs/hardware-runbook.md#d-devnet-with-node3-signing-in-the-guest).

## Gloas

Run with `GLOAS_EPOCH=<n>` (for example `2`, so the DV runs a few epochs in Fulu first). The default
images already support Gloas; tested 2026-11-19 with `GLOAS_EPOCH=2` for 160 slots:

| Component | Variable | Image |
|---|---|---|
| Execution client | `EL_IMAGE` | `ethereum/client-go:v1.17.10` (default) |
| Lighthouse BN and Kurtosis VC | `CL_IMAGE` | `sigp/lighthouse:v8.3.3` (default) |
| ethereum-package | `ETH_PKG` | `ObolNetwork/ethereum-package@6.1.0-obol.6` (default) |
| charon | `CHARON` | main from `e995d274` (Gloas duties, #4789) on |
| VCs | `LIGHTHOUSE`, `TEKU`, `LODESTAR`, `PRYSM` | the defaults: Lighthouse v8.3.3, Teku 26.10.3, Lodestar v1.50.1, Prysm v7.3.1 |

All four VCs signed every Gloas kind they use, with no rejections.

What to look for after the fork:
- The new kinds should appear in `summary`:
  - `PAYLOAD_ATTESTATION_MESSAGE` from PTC members;
  - `EXECUTION_PAYLOAD_ENVELOPE` after each DV proposal (self-build);
  - `PROPOSER_PREFERENCES`, if the VC sends them;
  - Gloas `AGGREGATE_AND_PROOF(_V2)`.
- Any `rejected` line means a request shape or version that the signer and that VC disagree on.
- A `refused` (412) envelope means the VC asked for an envelope for a block this signer did not sign.
- A VC that sends `EXECUTION_PAYLOAD_BID` gets 403 by design.
- `summary` adds a Gloas section: how many DV self-built payloads were revealed (`FULL`) and which
  were not, plus charon's `envelope never revealed` warnings. An `EMPTY` payload with signed envelopes
  on every signer points past the signer. In the 2026-11-19 run, charon submitted the envelope before
  the beacon node had imported the block, got `BlockRootUnknown`, and didn't retry.

## What it reports

**`summary`:**
- **dvtee, per node:**
  - signatures by `kind`;
  - `rejected` (400/403, the `rejected sign request` warning);
  - `refused` (412 slashing).
- **charon, per node:** distinct duties broadcast to the BN, and the tracker's `Duty failed` lines, by
  duty type.
  - These come from the logs, because charon's tracker metrics stay at 0 in this setup (charon starts
    before genesis). The tracker logs nothing then either, so an empty `failed:` line proves nothing.
  - Compare `aggregator` against `attester`: with 64 validators, every attester is an aggregator.
- **charon logs:** invalid-partial-signature lines and expired-duty drops.
- **Chain:** DV proposals that landed on chain, and DV balances.

**`checks`, all against signer0 with node0's pinned client certificate:**
1. **Malformed request:** an attestation with `source.epoch > target.epoch` should get 400, produce a
   `rejected sign request` line, and leave the slashing file unchanged.
2. **Replay:** replay the attestation from signer0's latest slashing record, taken from the chain. The
   identical body should get 200, and a different `beacon_block_root` should get 412.
3. **Restart:** `docker restart` of signer0 should log `shutting down` and exit 0 within its 5 s drain,
   not hit Docker's 10 s SIGKILL. It also reports how long until `/upcheck` answers again; the debug
   build takes about 11 s to decrypt 8 keystores.
4. **Replay after the restart:** the same two requests should get the same results. The 412 now comes
   from the persisted DB.

## What healthy looks like

- Every signer has `rejected=0` and `refused=0` during normal operation.
- Every VC signs `ATTESTATION`, `AGGREGATION_SLOT` and the sync-committee kinds:
  - Lighthouse and Teku sign `AGGREGATE_AND_PROOF`; Lodestar and Prysm sign `AGGREGATE_AND_PROOF_V2`.
  - Lighthouse also signs `VALIDATOR_REGISTRATION`.
- No charon node logs an invalid partial signature.
- From epoch 1 on, `aggregator` covers every `attester` slot, and every DV proposal is on chain.
- Epoch 0 is warm-up, because Prysm starts signing at about slot 27 and Lodestar aggregates from about
  slot 35. Until then, some aggregator and sync-contribution duties can't reach 3 of 4.

## Teardown

`down` removes the harness containers and the enclave. It leaves the Kurtosis engine running. To remove
everything Kurtosis created, run:

```sh
kurtosis engine stop
# Kurtosis 1.22 also leaves its otel ClickHouse and collector containers and a few volumes behind:
docker ps -a | grep kurtosis-otel
docker volume ls | grep kurtosis
```
