# Load test

How many signatures per slot one dvtee completes within the attestation deadline, with the
full duty mix of a charon distributed validator running alongside.

## Summary

Measured on a dev box (Ryzen 5 3600, consumer NVMe, ext4, no SNP), release build, TLS with mTLS,
slashing database fsynced on the NVMe. Real-slot equivalents: counts are per 12 s slot.

* **The 100 attestations per slot target is met, with margin on the median and little on the tail.**
  With 3200 keys (100 attestations and about 208 signatures per slot, all duty kinds), every request
  in three runs finished within 1 s. Attestations took 22 ms at the median. p99 was 33, 131 and
  985 ms in the three runs.
* **The tail is disk syncs, not signing.** Attestations and blocks wait for their watermark: a new
  file, an fsync, a rename and a directory fsync, about 9 ms on an idle disk. Now and then ext4
  journal commits slow down, and every watermark in flight waits. A probe doing the same writes saw
  single writes take up to 241 ms. With many writes queued in the signer, bursts took up to 1.9 s at
  realistic load. With 6400 keys (200 attestations per slot), 4 of 6 runs stayed under 1 s (p99
  50 to 235 ms). In the other 2, one or two slots went over (worst request 1.35 and 1.77 s).
  `AGGREGATION_SLOT`, which has no watermark, stayed under 37 ms in the same runs.
* **Ceiling without the disk.** With the database on tmpfs, 6400 attestations per slot (13,200
  signatures per slot, the most tested) completed with p99 440 ms. Signing and HTTP have more than
  60× headroom over the target on 6 cores.
* **Ceiling with the disk.** 800 attestations per slot passed once (p99 126 ms) and failed once on
  a single stalled slot. 1600 passed with 512 client connections (p99 486 ms) and failed with 128.
  On this disk the limit is the stall, not throughput.
* **Grouping the per-key file writes does not help.** The prototype syncs a batch of files and the
  directory once. On a quiet disk it was slower than the current code (median 47 vs 26 ms at 200
  per slot), because the kernel already shares journal commits between concurrent fsyncs. Neither
  of its two runs met a stall, so its effect on the tail is not measured. A store that needs no
  journal commit per write looks more promising. See [Next steps](#next-steps).

## Rerun it

From `signer/`, on the disk the signer's data dir will use:

```sh
scripts/load-test.sh
```

It builds `dvtee` and the load tool, runs the micro benchmarks, the realistic mix at 100, 1000,
3200 and 6400 keys, and the stress ramp, and writes the tables to `load-test-work/results-<time>/`.
With the defaults it takes 45 to 60 minutes. The variables at the top of the script change the
sizes, epochs, slot length, budget and transport.

Single runs:

```sh
cargo build --release --features load-test
target/release/dvtee-load micro
target/release/dvtee-load run --keys 3200
target/release/dvtee-load run --keys 6400 --attesters-per-slot 1600
target/release/dvtee-load probe --secs 600   # next to a run: logs sync stalls per second
target/release/dvtee-load run --help
```

The tool signs on a devnet of its own: Hoodi's fork schedule (or `--network`'s) under a load-test
genesis validators root. On Hoodi itself the start floor would be on, and it refuses the compressed
clock's epochs. On a devnet it is off by default, so the release binary is measured as built.

Against a signer that is already running, for example in an SNP guest with the tool on the host,
set that signer up on the same devnet:

```sh
# from signer/
target/release/dvtee-load devnet-config --out load-test-work/devnet
target/release/dvtee-load keygen --keys 3200      # load-test-work/keys-3200/
../scripts/make-provision-disk.sh -o prov.img -k load-test-work/keys-3200 \
  -c load-test-work/devnet/config.yaml -g "$(cat load-test-work/devnet/genesis-validators-root)" \
  -K knownClients.txt
target/release/dvtee-load run --url https://guest:9000 --ca cert.pem \
  --client-cert client.pem --client-key client.key --start-epoch 60000
```

`--start-epoch` must be above the previous run's: the tool prints the next one. A start epoch that
is too low fails with 412 slashing refusals, as it should.

## Method

**Workload.** In a charon cluster each operator's signer signs a share of every duty of every
validator. A signer with N keys therefore sees N/32 attestations per slot. The tool sends one
signer's per-slot mix, at the times charon's scheduler starts each duty:

| Time in slot | Requests |
|---|---|
| start | `AGGREGATION_SLOT` for every attester (each DV attester signs a selection proof); `SYNC_COMMITTEE_SELECTION_PROOF` per sync member; `RANDAO_REVEAL` and `BLOCK_V2` per proposal |
| 1/3 (4 s) | `ATTESTATION` for every attester; `SYNC_COMMITTEE_MESSAGE` per sync member |
| 2/3 (8 s) | `AGGREGATE_AND_PROOF_V2` for aggregators; `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` for sync aggregators |

* **Shares of the network.** With 1,000,000 active validators (`--total-validators`) a committee has
  about 490 members, so about 1 attester in 30 aggregates (16 per committee). A key holds
  512/1,000,000 of the sync committee seats, and 1 in 8 sync members aggregates. Proposals come at
  N/1,000,000 per slot. To always exercise them, the tool uses at least one sync member and one
  proposal per epoch, which overstates both for small N.
* **Well formed and not slashable.** Requests are Fulu requests on Hoodi's fork schedule (from epoch
  60000), built from that schedule. Attestation targets and block slots only increase per key. A unit test
  runs every generated request through the signer's own `prepare`. After a run the tool verifies a
  sample of signatures per kind against roots computed by the same code.
* **Compressed clock.** A simulated slot is 3 s by default, so bursts start 1 s apart instead of
  4 s. Latencies are real time, never scaled. The counts per slot are the counts of a 12 s slot. A
  burst that has not finished when the next one starts fails the run: on a real slot it would have
  had 4 s, so the compressed result would be too pessimistic. 32 warm-up slots come first and are
  not counted, so every key's watermark file exists. One run with real 12 s slots matched the
  compressed runs (attestation p99 53 ms at 200 per slot).
* **Stress mode** (`--attesters-per-slot K`). Each simulated slot is a new epoch, so the same key can
  attest in every slot. This gives K attestations per slot from fewer keys, plus the rest of the mix
  scaled to 32·K validators. It finds the ceiling without loading hundreds of thousands of keys.
* **Latency** is measured from the burst's start, the moment charon would ask, to the response. It
  includes time queued in the client. The budget is 1 s (`--budget-ms`). A run passes if every
  request succeeds, no burst overlaps the next, and p99 of every kind is within the budget.
* **Production path.** The tool starts the real `dvtee serve` binary, with TLS and a pinned
  client certificate (mTLS), and drives it over HTTP/1.1 keep-alive connections. Each of the 128
  connections has one request in flight. The slashing database is on the disk under test with
  every fsync. `--plain-http`, `--no-mtls`, `--http2` and `--data-parent /dev/shm` switch these
  off one at a time for the cost split.
* **Test keys.** EIP-2335 keystores with pbkdf2 at one iteration, derived from a public seed. The
  signer already accepts any pbkdf2 count, so no signer change or test-only mode is needed, and 6400
  keys load in about a second. Never deposit these keys.
* **Client on the same machine.** The tool runs with 2 runtime threads, so it competes with the
  signer for CPU. In the SNP setup the validator client is outside the guest, so `--url` from the
  host is closer to production.

## Machine

* AMD Ryzen 5 3600 (6 cores, 12 threads), 32 GB RAM, Linux 6.1, in a Docker container.
* Kingston NV2 4 TB NVMe (DRAM-less consumer drive, volatile write cache on), ext4 `data=ordered`,
  `commit=5`.
* Rust 1.100.0. Release builds use LTO and one codegen unit. The dev profile already builds blst,
  sha2, scrypt and pbkdf2 at opt-level 3, so debug and release sign at the same speed.
* Other builds were running on the same CPU and disk during most runs (load average 0.1 to 50).
  Each key number below was rerun, and every run is shown.

## Results

All runs: Hoodi Fulu (before the start floor existed; the load-test devnet now gives the same
signing path), HTTP/1.1 with 128 connections, TLS with mTLS, 3 s simulated slots, 32 warm-up
plus 64 measured slots (2 epochs), budget 1 s, unless the row says otherwise. Latency is for
`ATTESTATION`, in ms, from the start of the burst. Every run verified a sample of signatures for
every kind, and no request was refused.

### Realistic mix

| Keys | Att/slot | Sigs/slot | Build | p50 | p95 | p99 | max | Within 1 s | Verdict |
|---:|---:|---:|---|---:|---:|---:|---:|---:|---|
| 100 | 3 | 8.5 | release | 19.2 | 20.3 | 20.6 | 21.1 | 100% | pass |
| 1000 | 31 | 66 | release | 20.4 | 24.2 | 24.9 | 25.5 | 100% | pass |
| 1000 | 31 | 66 | debug | 21.4 | 26.1 | 28.7 | 29.7 | 100% | pass |
| 3200 | 100 | 208 | release | 23.7 | 151 | 985 | 993 | 100% | pass |
| 3200 | 100 | 208 | release | 22.4 | 27.5 | 32.7 | 34.0 | 100% | pass |
| 3200 | 100 | 208 | release | 22.1 | 30.2 | 131 | 175 | 100% | pass |
| 6400 | 200 | 413 | release | 47.1 | 316 | 1175 | 1770 | 99.46% | fail |
| 6400 | 200 | 413 | release | 47.7 | 209 | 671 | 1353 | 99.73% | fail |
| 6400 | 200 | 413 | release | 26.7 | 76.2 | 235 | 409 | 100% | pass |
| 6400 | 200 | 413 | release | 26.1 | 46.4 | 50.7 | 62.3 | 100% | pass |
| 6400 | 200 | 413 | release | 26.4 | 46.6 | 50.1 | 58.6 | 100% | pass |
| 6400 | 200 | 413 | release, 12 s slots, 1 epoch | 25.9 | 47.1 | 52.6 | 55.1 | 100% | pass |
| 6400 | 200 | 413 | debug | 32.9 | 54.7 | 62.1 | 77.8 | 100% | pass |

The two 6400-key failures each had one or two slots where a burst outlived the 1 s gap to the next
burst. `AGGREGATION_SLOT`, which needs no watermark, had p99 35 to 37 ms in the same runs.

### Where the time goes

At 200 attestations per slot, release:

| Variant | Attestation p50 | p99 | Attestation burst done (p50) |
|---|---:|---:|---:|
| TLS + mTLS, ext4 (baseline, quiet run) | 26.1 | 50.7 | 45 |
| plain HTTP, ext4 | 26.6 | 51.7 | n/a |
| TLS + mTLS, tmpfs (no fsync) | 14.5 | 26.1 | 20 |
| HTTP/2, one connection, ext4 (1 run) | 48.2 | 1112 | 75 |
| group commit prototype, ext4 (2 runs) | 47.2, 49.0 | 85.6, 102 | 75 |

In-process (`dvtee-load micro`), through `spawn_blocking` like the handler, median of 3 rounds,
range over 2 to 4 sessions:

| Burst | BLS sign only | Watermark only | Watermark + sign |
|---:|---:|---:|---:|
| 200 | 11 to 15 ms | 20 to 29 ms | 28 to 37 ms |
| 1000 | 51 to 56 ms | 92 to 103 ms | 140 to 151 ms |
| 3200 | 162 to 182 ms | 257 to 264 ms | 442 to 494 ms |

Serially: one BLS signature takes 0.33 ms, one watermark write 9 ms (two fsyncs), and an in-place
overwrite of a preallocated file with `fdatasync` 0.7 ms. The same overwrites in bursts, each with
its own `fdatasync` and no batching: 200 in 21 ms, 1000 in 44 ms, 3200 in 146 ms. That matches
today's watermark writes at 200 and is about twice as fast at 1000 and more.

So for a 200-attestation burst (about 45 ms end to end): BLS signing is about 12 ms of CPU spread
over the cores, watermark syncs about 25 ms, and TLS, HTTP and JSON the rest. TLS costs nothing
measurable at this rate, since connections are kept alive. HTTP/2 over a single connection was
slower than an HTTP/1.1 pool in its one run, though two early HTTP/1.1 runs also had a 47 ms median.

### Stress mode

6400 keys, K attestations per slot, the rest of the mix scaled to 32·K validators.

| Att/slot | Sigs/slot | Data dir | Client conns | Att p50 | p99 | max | Burst done p50 | Verdict |
|---:|---:|---|---:|---:|---:|---:|---:|---|
| 800 | 1654 | ext4 | 128 | 66.4 | 126 | 146 | 120 | pass (1 epoch, 8 warm-up slots) |
| 800 | 1654 | ext4 | 128 | 69.2 | 654 | 1262 | 122 | fail (one slot) |
| 1600 | 3308 | ext4 | 128 | 123 | 1254 | 1893 | 224 | fail |
| 1600 | 3308 | ext4 | 512 | 143 | 486 | 632 | 237 | pass |
| 3200 | 6616 | ext4 | 128 | 228 | 1786 | 2515 | 424 | fail |
| 3200 | 6616 | tmpfs | 128 | 126 | 237 | 278 | 227 | pass (1 epoch) |
| 6400 | 13233 | ext4 | 128 | 525 | 4851 | 5188 | 862 | fail (1 epoch) |
| 6400 | 13233 | tmpfs | 128 | 221 | 440 | 487 | 431 | pass (1 epoch) |

With more connections, more fsyncs are in flight together and share journal commits. A validator
client's connection pool size therefore matters at high rates.

### Disk stalls

`dvtee-load probe` ran next to the signer in the second round of 10 runs. Each second it
timed ten in-place overwrites with `fdatasync` (A) and ten signer-style watermark writes (B), and
logged the slowest of each:

* B had seconds over 50 ms (up to 241 ms) in 6 runs: the one realistic run in that round with an
  attestation p99 over 100 ms (131 ms), all four stress runs, and the 12 s slot run, where the stall
  fell in the warm-up. The four runs without B stalls had attestation p99 of 33 to 86 ms.
* A stayed under 27 ms in every realistic run. Under stress load it went over 50 ms in 7 seconds
  (max 78 ms), against 75 seconds for B.
* In the stall looked at closely, the drive was writing only 1 to 3 MB/s while
  `/proc/pressure/io` rose to 24%. The stalls follow ext4 journal commits, not write volume.

## Caveats

* **Not an SNP guest.** Memory encryption should cost little for BLS, which is compute-bound in
  cache. Disk I/O in a guest goes through the host, and the data disk will be dm-crypt over a
  virtual disk, so the fsync path, which dominates here, can change a lot. Rerun `scripts/load-test.sh`
  in the guest, on its real data disk, and run `probe` there too.
* **A consumer drive shared with other work.** A datacenter NVMe with power-loss protection
  completes flushes much faster. A host shared with other VMs can also stall. The stall rate here is
  a property of this box.
* **The client shares the CPU.** The tool's TLS client and JSON use 2 threads on the same machine.
* **The compressed clock** writes four times as much per minute as real slots. One 12 s run matched,
  but stalls tied to elapsed time may be under-sampled.
* **Assumed timing.** Selection proofs are sent at the start of the slot, as charon's aggregation
  needs them before 2/3 of the slot. Validator clients that precompute them per epoch spread that
  load out.
* **The verdict is strict.** One stalled slot in 64 fails a run. That is on purpose: a late
  attestation partial is a missed duty for that operator.

## Next steps

* **A watermark store without a journal commit per write.** For example, fixed-size records per key
  in a preallocated file, written in place with a checksum and an `fdatasync`, with two slots per
  key against torn writes. That is 0.7 ms instead of 9 ms serially, and about the same or faster in
  bursts. It went over 50 ms only under stress load (max 78 ms), against 241 ms for today's write
  pattern. Batching several records into one `fdatasync` would be the real group commit. Measure it
  with this tool before adopting it.
* **The per-file group commit prototype** measured above was dropped before merge. It kept the
  file format and synced a batch of files plus the directory once. It was slower on a quiet disk,
  and its tail under stalls was not measured.
* **Client concurrency.** At 1600 attestations per slot, 512 client connections passed where 128
  failed: more fsyncs in flight share each journal commit. Charon and validator client pool sizes
  are worth checking at high key counts.
* Rerun on SNP hardware, including `--url` from the host.
