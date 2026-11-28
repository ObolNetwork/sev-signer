//! Compares the built-in network presets with the upstream configs, so a fork
//! scheduled (or unscheduled) upstream shows up as a failing check instead of
//! a signer that refuses requests at the fork.
//!
//! Runs only when `UPSTREAM_CONFIGS_DIR` holds `mainnet.yaml`, `hoodi.yaml` and
//! `sepolia.yaml` (`scripts/fetch-upstream-configs.sh` fetches them); the
//! scheduled `presets` workflow does that daily.

use dvtee::network::{FAR_FUTURE_EPOCH, Network};

#[test]
fn presets_match_upstream() {
    let Ok(dir) = std::env::var("UPSTREAM_CONFIGS_DIR") else {
        eprintln!("UPSTREAM_CONFIGS_DIR not set; skipping");
        return;
    };
    let mut drift = Vec::new();
    for preset in Network::presets() {
        let path = std::path::Path::new(&dir).join(format!("{}.yaml", preset.name));
        let cfg =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let upstream = Network::from_config_yaml(&cfg, preset.genesis_validators_root)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for (ours, theirs) in preset.forks.iter().zip(&upstream.forks) {
            // An unscheduled fork's version doesn't matter (upstream often
            // drops it with the epoch).
            let unscheduled = ours.epoch == FAR_FUTURE_EPOCH && theirs.epoch == FAR_FUTURE_EPOCH;
            if ours != theirs && !unscheduled {
                drift.push(format!(
                    "{}: preset has {:?}, upstream has {:?}",
                    preset.name, ours, theirs
                ));
            }
        }
        if preset.forks.len() != upstream.forks.len() {
            drift.push(format!(
                "{}: preset has {} forks, upstream {}",
                preset.name,
                preset.forks.len(),
                upstream.forks.len()
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "presets differ from upstream; update Network::presets() and release:\n{}",
        drift.join("\n")
    );
}
