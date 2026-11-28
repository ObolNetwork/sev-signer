//! The per-slot duty mix of one charon DV signer, as Web3Signer requests.
//!
//! In a charon cluster every operator's signer signs a share for every duty
//! of every validator, so one signer with N keys sees, per slot:
//! * N/32 attestations (one per validator per epoch), at 1/3 of the slot;
//! * N/32 beacon committee selection proofs, at the start of the slot: every
//!   attester signs one, because only the aggregated proof shows whether the
//!   validator aggregates;
//! * aggregates from the attesters that turn out to be aggregators (about
//!   16 per committee), at 2/3 of the slot;
//! * for each sync committee member, a selection proof per subcommittee at
//!   the start of the slot, a sync message at 1/3 and, for about 1 in 8, a
//!   contribution at 2/3;
//! * for each proposal, a RANDAO reveal and a block header at the start.
//!
//! Every request is well formed for the network and is not slashable:
//! attestation targets and block slots only increase per key.

use std::sync::Arc;

use hyper::body::Bytes;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use dvtee::network::{FAR_FUTURE_EPOCH, Network, SLOTS_PER_EPOCH};

/// The three times in a slot at which duties start, as in charon's
/// scheduler: slot start, 1/3 and 2/3.
pub const PHASES: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Randao,
    Block,
    SelectionProof,
    Attestation,
    Aggregate,
    SyncSelectionProof,
    SyncMessage,
    SyncContribution,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::Attestation,
        Kind::SelectionProof,
        Kind::Aggregate,
        Kind::SyncMessage,
        Kind::SyncSelectionProof,
        Kind::SyncContribution,
        Kind::Randao,
        Kind::Block,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Randao => "RANDAO_REVEAL",
            Kind::Block => "BLOCK_V2",
            Kind::SelectionProof => "AGGREGATION_SLOT",
            Kind::Attestation => "ATTESTATION",
            Kind::Aggregate => "AGGREGATE_AND_PROOF_V2",
            Kind::SyncSelectionProof => "SYNC_COMMITTEE_SELECTION_PROOF",
            Kind::SyncMessage => "SYNC_COMMITTEE_MESSAGE",
            Kind::SyncContribution => "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Mix {
    /// Keys loaded in the signer.
    pub keys: usize,
    /// `Some(k)`: stress mode. `k` keys attest in every simulated slot and
    /// each simulated slot is a new epoch, so a key can attest every slot.
    /// `None`: keys attest once per epoch, `keys / 32` per slot.
    pub stress_attesters: Option<usize>,
    pub aggregator_ratio: f64,
    pub sync_members: usize,
    pub proposals_per_slot: f64,
}

impl Mix {
    /// `total_validators` (active validators on the network) sets the
    /// committee size, and so the aggregator share, and the sync committee
    /// and proposal shares.
    pub fn new(
        keys: usize,
        stress_attesters: Option<usize>,
        total_validators: u64,
        aggregator_ratio: Option<f64>,
        sync_members: Option<usize>,
    ) -> Self {
        // Validators this load stands for: a stress run with k attesters
        // per slot is the attestation load of 32k validators.
        let equiv = stress_attesters.map_or(keys, |k| k * 32) as f64;
        let total = total_validators as f64;
        // TARGET_AGGREGATORS_PER_COMMITTEE / committee size.
        let committee = (total / (SLOTS_PER_EPOCH as f64 * 64.0)).max(1.0);
        let aggregator_ratio = aggregator_ratio.unwrap_or((16.0 / committee).min(1.0));
        // Expected share of the 512 sync committee seats, at least one so
        // the sync path is always exercised.
        let sync_members = sync_members
            .unwrap_or(((512.0 * equiv / total).round() as usize).max(1))
            .min(keys);
        // Expected proposals, at least one per epoch so blocks are always
        // exercised.
        let proposals_per_slot = (equiv / total).max(1.0 / SLOTS_PER_EPOCH as f64);
        Mix {
            keys,
            stress_attesters,
            aggregator_ratio,
            sync_members,
            proposals_per_slot,
        }
    }

    pub fn attesters_per_slot(&self) -> f64 {
        self.stress_attesters
            .map_or(self.keys as f64 / SLOTS_PER_EPOCH as f64, |k| k as f64)
    }

    fn stride(&self) -> u64 {
        if self.stress_attesters.is_some() {
            SLOTS_PER_EPOCH
        } else {
            1
        }
    }
}

pub struct Request {
    pub kind: Kind,
    pub key: usize,
    pub body: Bytes,
}

pub struct Slot {
    pub phases: [Vec<Request>; PHASES],
}

pub struct Schedule {
    mix: Mix,
    net: Network,
    start_slot: u64,
    cursor: usize,
    next_proposer: usize,
    acc_aggregate: f64,
    acc_proposal: f64,
    acc_contribution: f64,
}

fn root(tag: &str, n: u64) -> String {
    let h: [u8; 32] = Sha256::new()
        .chain_update(tag.as_bytes())
        .chain_update(n.to_le_bytes())
        .finalize()
        .into();
    format!("0x{}", hex::encode(h))
}

fn sig_placeholder(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 96]))
}

impl Schedule {
    pub fn new(mix: Mix, net: Network, start_epoch: u64) -> Self {
        Schedule {
            mix,
            net,
            start_slot: start_epoch * SLOTS_PER_EPOCH,
            cursor: 0,
            next_proposer: 0,
            acc_aggregate: 0.0,
            acc_proposal: 0.0,
            acc_contribution: 0.0,
        }
    }

    /// First epoch after a run of `slots` simulated slots, for a rerun
    /// against the same database.
    pub fn next_start_epoch(&self, slots: usize) -> u64 {
        (self.start_slot + slots as u64 * self.mix.stride()) / SLOTS_PER_EPOCH + 1
    }

    /// `fork_info` and the fork name (V2 `version`) at `epoch`.
    fn fork_info(&self, epoch: u64) -> (Value, String) {
        let forks = &self.net.forks;
        let idx = forks
            .iter()
            .rposition(|f| f.epoch != FAR_FUTURE_EPOCH && f.epoch <= epoch)
            .expect("network has a fork schedule");
        let cur = forks[idx];
        let prev = if idx > 0 {
            forks[idx - 1].version
        } else {
            cur.version
        };
        let fi = json!({
            "fork": {
                "previous_version": format!("0x{}", hex::encode(prev)),
                "current_version": format!("0x{}", hex::encode(cur.version)),
                "epoch": cur.epoch.to_string(),
            },
            "genesis_validators_root": format!("0x{}", hex::encode(self.net.genesis_validators_root)),
        });
        (fi, cur.name.as_str().to_uppercase())
    }

    /// Simulated slot `i` (0-based from the start of the run).
    pub fn slot(&mut self, i: usize) -> Slot {
        let mix = self.mix.clone();
        let slot = self.start_slot + i as u64 * mix.stride();
        let epoch = slot / SLOTS_PER_EPOCH;
        let (fi, version) = self.fork_info(epoch);
        let bbr = root("block", slot);
        let mut phases: [Vec<Request>; PHASES] = Default::default();
        let mut push = |phase: usize, kind: Kind, key: usize, v: Value| {
            phases[phase].push(Request {
                kind,
                key,
                body: Bytes::from(v.to_string()),
            });
        };
        let vindex = |key: usize| (100_000 + key).to_string();

        // Proposals.
        self.acc_proposal += mix.proposals_per_slot;
        while self.acc_proposal >= 1.0 {
            self.acc_proposal -= 1.0;
            let key = self.next_proposer % mix.keys;
            self.next_proposer += 1;
            push(
                0,
                Kind::Randao,
                key,
                json!({"type": "RANDAO_REVEAL", "fork_info": fi, "randao_reveal": {"epoch": epoch.to_string()}}),
            );
            push(
                0,
                Kind::Block,
                key,
                json!({"type": "BLOCK_V2", "fork_info": fi, "beacon_block": {
                    "version": version,
                    "block_header": {
                        "slot": slot.to_string(),
                        "proposer_index": vindex(key),
                        "parent_root": root("block", slot - 1),
                        "state_root": root("state", slot),
                        "body_root": root("body", slot),
                    },
                }}),
            );
        }

        // Attesters.
        let attesters: Vec<usize> = match mix.stress_attesters {
            None => (0..mix.keys)
                .filter(|k| *k as u64 % SLOTS_PER_EPOCH == slot % SLOTS_PER_EPOCH)
                .collect(),
            Some(k) => {
                let v = (0..k).map(|j| (self.cursor + j) % mix.keys).collect();
                self.cursor = (self.cursor + k) % mix.keys;
                v
            }
        };
        // Electra and later: the committee is in `committee_bits`, and the
        // data's `index` is 0.
        let data = json!({
            "slot": slot.to_string(),
            "index": "0",
            "beacon_block_root": bbr,
            "source": {"epoch": (epoch - 1).to_string(), "root": root("checkpoint", epoch - 1)},
            "target": {"epoch": epoch.to_string(), "root": root("checkpoint", epoch)},
        });
        for (j, &key) in attesters.iter().enumerate() {
            let committee = j % 64;
            push(
                0,
                Kind::SelectionProof,
                key,
                json!({"type": "AGGREGATION_SLOT", "fork_info": fi, "aggregation_slot": {"slot": slot.to_string()}}),
            );
            push(
                1,
                Kind::Attestation,
                key,
                json!({"type": "ATTESTATION", "fork_info": fi, "attestation": data}),
            );
            self.acc_aggregate += mix.aggregator_ratio;
            if self.acc_aggregate >= 1.0 {
                self.acc_aggregate -= 1.0;
                let mut committee_bits = [0u8; 8];
                committee_bits[committee / 8] |= 1 << (committee % 8);
                // 64 attesters plus the bitlist length bit.
                let mut aggregation_bits = [0xffu8; 9];
                aggregation_bits[8] = 0x01;
                push(
                    2,
                    Kind::Aggregate,
                    key,
                    json!({"type": "AGGREGATE_AND_PROOF_V2", "fork_info": fi, "aggregate_and_proof": {
                        "version": version,
                        "data": {
                            "aggregator_index": vindex(key),
                            "selection_proof": sig_placeholder(0x0b),
                            "aggregate": {
                                "aggregation_bits": format!("0x{}", hex::encode(aggregation_bits)),
                                "committee_bits": format!("0x{}", hex::encode(committee_bits)),
                                "data": data,
                                "signature": sig_placeholder(0x0a),
                            },
                        },
                    }}),
                );
            }
        }

        // Sync committee members: the first `sync_members` keys.
        for key in 0..mix.sync_members {
            let subcommittee = (key % 4).to_string();
            push(
                0,
                Kind::SyncSelectionProof,
                key,
                json!({"type": "SYNC_COMMITTEE_SELECTION_PROOF", "fork_info": fi,
                    "sync_aggregator_selection_data": {"slot": slot.to_string(), "subcommittee_index": subcommittee}}),
            );
            push(
                1,
                Kind::SyncMessage,
                key,
                json!({"type": "SYNC_COMMITTEE_MESSAGE", "fork_info": fi,
                    "sync_committee_message": {"beacon_block_root": bbr, "slot": slot.to_string()}}),
            );
            // TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE / subcommittee size.
            self.acc_contribution += 16.0 / 128.0;
            if self.acc_contribution >= 1.0 {
                self.acc_contribution -= 1.0;
                push(
                    2,
                    Kind::SyncContribution,
                    key,
                    json!({"type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", "fork_info": fi,
                    "contribution_and_proof": {
                        "aggregator_index": vindex(key),
                        "selection_proof": sig_placeholder(0x0f),
                        "contribution": {
                            "slot": slot.to_string(),
                            "beacon_block_root": bbr,
                            "subcommittee_index": subcommittee,
                            "aggregation_bits": format!("0x{}", hex::encode([0xffu8; 16])),
                            "signature": sig_placeholder(0x0e),
                        },
                    }}),
                );
            }
        }

        Slot { phases }
    }
}

/// Shared, cheaply clonable request paths.
pub fn sign_paths(pubkeys: &[String]) -> Arc<Vec<String>> {
    Arc::new(
        pubkeys
            .iter()
            .map(|pk| format!("/api/v1/eth2/sign/{pk}"))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvtee::signing::{Policy, SignRequest, prepare};

    fn hoodi() -> Network {
        Network::presets()
            .into_iter()
            .find(|n| n.name == "hoodi")
            .unwrap()
    }

    /// Every generated request passes the signer's own validation, and
    /// attestation targets and block slots increase per key.
    #[test]
    fn requests_are_valid_and_not_slashable() {
        let net = hoodi();
        let policy = Policy {
            allow_voluntary_exits: false,
            allow_deposits: false,
        };
        for stress in [None, Some(40)] {
            let mix = Mix::new(64, stress, 1_000, None, None);
            let mut s = Schedule::new(mix, net.clone(), 60_000);
            let mut last_target = std::collections::HashMap::new();
            let mut last_block = std::collections::HashMap::new();
            let mut kinds = std::collections::BTreeSet::new();
            for i in 0..70 {
                let slot = s.slot(i);
                for r in slot.phases.iter().flatten() {
                    kinds.insert(r.kind);
                    let req: SignRequest = serde_json::from_slice(&r.body).unwrap();
                    let p = prepare(&req, &net, &policy)
                        .unwrap_or_else(|e| panic!("{}: {e}", r.kind.name()));
                    assert_eq!(p.kind, r.kind.name());
                    match p.slashing {
                        Some(dvtee::signing::SlashingCheck::Attestation { target, .. }) => {
                            let prev = last_target.insert(r.key, target);
                            assert!(prev.is_none_or(|t| t < target), "target reused");
                        }
                        Some(dvtee::signing::SlashingCheck::Block { slot, .. }) => {
                            let prev = last_block.insert(r.key, slot);
                            assert!(prev.is_none_or(|t| t < slot), "block slot reused");
                        }
                        _ => {}
                    }
                }
            }
            assert_eq!(kinds.len(), Kind::ALL.len(), "{stress:?}: {kinds:?}");
        }
    }
}
