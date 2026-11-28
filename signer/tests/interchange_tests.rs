//! The EIP-3076 interchange test suite (eth-clients/slashing-protection-interchange-tests),
//! fetched by `scripts/fetch-interchange-tests.sh`, run against the slashing database.
//!
//! For each test: open an empty database for the test's genesis validators root, then for
//! each step import the interchange and try each block and attestation in order. The
//! database keeps one low watermark per key (the minimal strategy), so results are compared
//! with `should_succeed`, the field for minimal implementations. `should_succeed_complete`
//! is only used to tell a safety failure (signing what a complete implementation would also
//! refuse) from a liveness difference.
//!
//! `contains_slashable_data` (which replaced `allow_partial_import` in v5.1.0): the import
//! may then fail, and if it does the rest of the test is skipped. Our import keeps only the
//! maximum slot and epochs, so it never fails on slashable data, and the checks must pass.
//!
//! Skipped unless `INTERCHANGE_TESTS_DIR` points at the fetched directory.

use std::path::PathBuf;

use dvtee::signing::SlashingCheck;
use dvtee::slashing::{SlashingDb, SlashingError};
use serde::Deserialize;

/// Number of test files in v5.3.0. Fewer means a broken fetch, not a pass.
const EXPECTED_TESTS: usize = 38;

#[derive(Deserialize)]
struct Test {
    name: String,
    genesis_validators_root: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    should_succeed: bool,
    contains_slashable_data: bool,
    interchange: serde_json::Value,
    blocks: Vec<Block>,
    attestations: Vec<Attestation>,
}

#[derive(Deserialize)]
struct Block {
    pubkey: String,
    slot: String,
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: bool,
}

#[derive(Deserialize)]
struct Attestation {
    pubkey: String,
    source_epoch: String,
    target_epoch: String,
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: bool,
}

/// Checks where the database signs although `should_succeed` is false, but
/// `should_succeed_complete` is true: a liveness difference, never a slashable
/// signature. Listed per case so a new deviation fails the test.
///
/// None today. Imported records carry no signing root (the database keeps only
/// the watermark), so an identical re-sign of an imported message is refused,
/// as the minimal strategy expects; only messages signed by this database are
/// re-signed.
const ALLOWED_LIVENESS_DEVIATIONS: &[(&str, &str)] = &[];

fn root(s: &Option<String>) -> [u8; 32] {
    let mut r = [0u8; 32];
    if let Some(s) = s {
        hex::decode_to_slice(s.trim_start_matches("0x"), &mut r).unwrap();
    }
    r
}

fn pubkey(s: &str) -> [u8; 48] {
    hex::decode(s.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

/// Compares one signing attempt with the expected result. Returns a failure
/// message, or `None` if it is fine.
fn judge(
    test: &str,
    what: &str,
    result: Result<(), SlashingError>,
    minimal: bool,
    complete: bool,
) -> Option<String> {
    match (result, minimal) {
        (Ok(()), true) | (Err(SlashingError::Violation(_)), false) => None,
        (Err(e), true) => Some(format!("{test}: {what} refused, should succeed: {e}")),
        (Ok(()), false) if !complete => Some(format!(
            "{test}: {what} SIGNED, but even a complete implementation must refuse it"
        )),
        (Ok(()), false) => {
            if ALLOWED_LIVENESS_DEVIATIONS.contains(&(test, what)) {
                None
            } else {
                Some(format!(
                    "{test}: {what} signed; minimal implementations refuse it \
                     (complete ones may sign it)"
                ))
            }
        }
        (Err(e), false) => Some(format!("{test}: {what} failed with a database error: {e}")),
    }
}

fn run(test: &Test) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let db = SlashingDb::open(
        dir.path(),
        root(&Some(test.genesis_validators_root.clone())),
    )
    .unwrap();
    let mut failures = Vec::new();

    for (i, step) in test.steps.iter().enumerate() {
        match db.import(step.interchange.to_string().as_bytes()) {
            Ok(_) if !step.should_succeed => {
                failures.push(format!("{}: step {i} imported, should fail", test.name));
                return failures;
            }
            Ok(_) => {}
            Err(_) if !step.should_succeed => return failures,
            Err(e) if step.contains_slashable_data => {
                // Allowed by the suite, but our import is expected to minify.
                failures.push(format!(
                    "{}: step {i} import refused slashable data ({e}); it should keep the maximum",
                    test.name
                ));
                return failures;
            }
            Err(e) => {
                failures.push(format!("{}: step {i} import failed: {e}", test.name));
                return failures;
            }
        }

        for (j, b) in step.blocks.iter().enumerate() {
            let check = SlashingCheck::Block {
                slot: b.slot.parse().unwrap(),
                block_root: root(&b.signing_root),
            };
            let res = db.check_and_record(&pubkey(&b.pubkey), check, &root(&b.signing_root));
            let what = format!("step {i} block {j} (slot {})", b.slot);
            failures.extend(judge(
                &test.name,
                &what,
                res,
                b.should_succeed,
                b.should_succeed_complete,
            ));
        }
        for (j, a) in step.attestations.iter().enumerate() {
            let check = SlashingCheck::Attestation {
                source: a.source_epoch.parse().unwrap(),
                target: a.target_epoch.parse().unwrap(),
            };
            let res = db.check_and_record(&pubkey(&a.pubkey), check, &root(&a.signing_root));
            let what = format!(
                "step {i} attestation {j} ({} -> {})",
                a.source_epoch, a.target_epoch
            );
            failures.extend(judge(
                &test.name,
                &what,
                res,
                a.should_succeed,
                a.should_succeed_complete,
            ));
        }
    }
    failures
}

#[test]
fn interchange_tests() {
    let Some(dir) = std::env::var_os("INTERCHANGE_TESTS_DIR").map(PathBuf::from) else {
        eprintln!(
            "INTERCHANGE_TESTS_DIR not set; run scripts/fetch-interchange-tests.sh. Skipping."
        );
        return;
    };
    let mut paths: Vec<_> = std::fs::read_dir(dir.join("generated"))
        .expect("INTERCHANGE_TESTS_DIR/generated")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    assert!(
        paths.len() >= EXPECTED_TESTS,
        "found {} interchange tests, expected {EXPECTED_TESTS}",
        paths.len()
    );

    let mut failures = Vec::new();
    let mut checks = 0;
    for path in &paths {
        let test: Test = serde_json::from_slice(&std::fs::read(path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        checks += test
            .steps
            .iter()
            .map(|s| s.blocks.len() + s.attestations.len())
            .sum::<usize>();
        failures.extend(run(&test));
    }
    eprintln!(
        "interchange tests: {} files, {checks} checks, {} failures",
        paths.len(),
        failures.len()
    );
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
