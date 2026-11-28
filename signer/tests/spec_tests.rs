//! hash_tree_root checks against external test data fetched by
//! `scripts/fetch-spec-tests.sh` (not vendored: ~1 GB upstream archive):
//!
//! - ethereum/ssz-specs fixtures for progressive lists, bitlists and
//!   containers, with gaps and level boundaries (`ssz-generic/`);
//! - consensus-specs release vectors, `ssz_static` for every container the
//!   signer hashes (`mainnet/<fork>/ssz_static/`).
//!
//! Skipped unless `SPEC_TESTS_DIR` points at the fetched directory.

use std::path::{Path, PathBuf};

use dvtee::signing::{
    AggregateAndProof, Attestation, AttestationData, AttestationSchema, BeaconBlockHeader,
    ExecutionPayload, ExecutionPayloadEnvelope, ExecutionRequests, PayloadAttestationData,
    ProposerPreferences, Withdrawal,
};
use dvtee::ssz::{self, Root};
use serde::de::DeserializeOwned;
use serde_json::Value;

fn spec_dir() -> Option<PathBuf> {
    match std::env::var_os("SPEC_TESTS_DIR") {
        Some(d) => Some(PathBuf::from(d)),
        None => {
            eprintln!("SPEC_TESTS_DIR not set; run scripts/fetch-spec-tests.sh. Skipping.");
            None
        }
    }
}

fn hex_root(s: &str) -> Root {
    let mut r = [0u8; 32];
    hex::decode_to_slice(s.trim_start_matches("0x"), &mut r).unwrap();
    r
}

// ---------------------------------------------------------------------------
// ssz-specs v0.1.0 progressive fixtures. The fixture types are defined in
// tests/fillers/ssz/test_progressive_{types,containers}.py of that release.

fn uint(v: &Value, bytes: usize) -> Vec<u8> {
    let n = v.as_u64().unwrap();
    n.to_le_bytes()[..bytes].to_vec()
}

fn uint_root(v: &Value, bytes: usize) -> Root {
    ssz::pack(&uint(v, bytes))[0]
}

fn data(v: &Value) -> &Vec<Value> {
    v["data"].as_array().unwrap()
}

fn uint_plist(v: &Value, bytes: usize) -> Root {
    let ser: Vec<u8> = data(v).iter().flat_map(|x| uint(x, bytes)).collect();
    ssz::progressive_list_packed(&ser, data(v).len())
}

fn bits_plist(v: &Value) -> Root {
    // Serialize with the delimiter bit to exercise the bitlist parsing.
    let bits: Vec<bool> = data(v).iter().map(|b| b.as_bool().unwrap()).collect();
    let mut ser = vec![0u8; (bits.len() + 1).div_ceil(8)];
    for (i, b) in bits.iter().chain([&true]).enumerate() {
        if *b {
            ser[i / 8] |= 1 << (i % 8);
        }
    }
    ssz::progressive_bitlist(&ser).unwrap()
}

fn layout(bits: &[u8]) -> Vec<bool> {
    bits.iter().map(|b| *b == 1).collect()
}

fn square(v: &Value) -> Root {
    ssz::progressive_container(
        &layout(&[1, 0, 1]),
        &[uint_root(&v["side"], 2), uint_root(&v["color"], 1)],
    )
}

fn generic_root(type_name: &str, v: &Value) -> Option<Root> {
    Some(match type_name {
        "SampleUint64ProgressiveList" => uint_plist(v, 8),
        "SampleUint16ProgressiveList" => uint_plist(v, 2),
        "SampleBytes32ProgressiveList" => {
            let roots: Vec<Root> = data(v)
                .iter()
                .map(|x| hex_root(x.as_str().unwrap()))
                .collect();
            ssz::progressive_list(&roots)
        }
        "SampleNestedProgressiveList" => {
            let roots: Vec<Root> = data(v).iter().map(|x| uint_plist(x, 2)).collect();
            ssz::progressive_list(&roots)
        }
        "ProgressiveBitList" => bits_plist(v),
        "SampleContainerWithProgressiveList" => ssz::container(&[
            uint_root(&v["a"], 2),
            uint_plist(&v["b"], 8),
            uint_root(&v["c"], 1),
        ]),
        "SampleSquare" => square(v),
        "SampleCircle" => ssz::progressive_container(
            &layout(&[0, 1, 1]),
            &[uint_root(&v["radius"], 2), uint_root(&v["color"], 1)],
        ),
        "SampleOneField" => ssz::progressive_container(&[true], &[uint_root(&v["a"], 2)]),
        "SampleLeadingGaps" => {
            ssz::progressive_container(&layout(&[0, 0, 1]), &[uint_root(&v["c"], 4)])
        }
        "SampleMultipleGaps" => ssz::progressive_container(
            &layout(&[1, 0, 0, 1, 0, 1]),
            &[
                uint_root(&v["a"], 1),
                uint_root(&v["b"], 2),
                uint_root(&v["c"], 4),
            ],
        ),
        "SampleWidestLayout" => {
            let mut l = vec![false; 256];
            l[255] = true;
            ssz::progressive_container(&l, &[uint_root(&v["tail"], 1)])
        }
        "SampleLevelBoundary" => {
            let mut l = vec![false; 22];
            l[0] = true;
            l[21] = true;
            ssz::progressive_container(&l, &[uint_root(&v["first"], 2), uint_root(&v["last"], 1)])
        }
        "SampleBoundedListField" => {
            // body: List[Uint16, 4] packs into one chunk.
            let body = &v["body"];
            let ser: Vec<u8> = data(body).iter().flat_map(|x| uint(x, 2)).collect();
            let body_root =
                ssz::mix_in_length(&ssz::merkleize(&ssz::pack(&ser), Some(1)), data(body).len());
            ssz::progressive_container(&layout(&[1, 0, 1]), &[uint_root(&v["head"], 8), body_root])
        }
        "SampleProgressiveFields" => ssz::progressive_container_dense(&[
            uint_root(&v["head"], 8),
            uint_plist(&v["numbers"], 8),
            bits_plist(&v["flags"]),
        ]),
        "SampleOuterShape" => {
            let inner = &v["inner"];
            let inner_root = ssz::progressive_container(
                &layout(&[1, 0, 1]),
                &[uint_root(&inner["x"], 2), uint_root(&inner["y"], 1)],
            );
            ssz::progressive_container(&layout(&[1, 0, 1]), &[uint_root(&v["head"], 1), inner_root])
        }
        "SampleSquareProgressiveList" => {
            let roots: Vec<Root> = data(v).iter().map(square).collect();
            ssz::progressive_list(&roots)
        }
        "SampleShapeContainer" => ssz::container(&[uint_root(&v["tag"], 1), square(&v["shape"])]),
        _ => return None,
    })
}

#[test]
fn ssz_generic_progressive() {
    let Some(dir) = spec_dir() else { return };
    let (mut passed, mut skipped) = (0, Vec::new());
    for sub in ["test_progressive_types", "test_progressive_containers"] {
        let mut files: Vec<_> = std::fs::read_dir(dir.join("ssz-generic").join(sub))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for path in files {
            let fixture: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            for (id, case) in fixture.as_object().unwrap() {
                let Some(root) = case
                    .get("root")
                    .and_then(Value::as_str)
                    .filter(|r| !r.is_empty())
                else {
                    skipped.push(format!("{id} (no root: decode-failure case)"));
                    continue;
                };
                let type_name = case["typeName"].as_str().unwrap();
                let got = generic_root(type_name, &case["value"])
                    .unwrap_or_else(|| panic!("{id}: unhandled type {type_name}"));
                assert_eq!(hex::encode(got), root.trim_start_matches("0x"), "{id}");
                passed += 1;
            }
        }
    }
    eprintln!(
        "ssz-generic progressive: {passed} passed, {} skipped",
        skipped.len()
    );
    for s in &skipped {
        eprintln!("  skipped {s}");
    }
    assert!(passed >= 30, "expected the full progressive fixture set");
}

// ---------------------------------------------------------------------------
// consensus-specs ssz_static.

type Hasher = fn(Value) -> Result<Root, String>;

fn de<T: DeserializeOwned>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|e| e.to_string())
}

fn hasher(fork: &str, type_name: &str) -> Hasher {
    let schema = match fork {
        "gloas" => AttestationSchema::Gloas,
        "fulu" | "electra" => AttestationSchema::Electra,
        _ => AttestationSchema::Phase0,
    };
    match (type_name, schema) {
        ("Attestation", AttestationSchema::Gloas) => {
            |v| de::<Attestation>(v)?.root(AttestationSchema::Gloas)
        }
        ("Attestation", AttestationSchema::Electra) => {
            |v| de::<Attestation>(v)?.root(AttestationSchema::Electra)
        }
        ("Attestation", AttestationSchema::Phase0) => {
            |v| de::<Attestation>(v)?.root(AttestationSchema::Phase0)
        }
        ("AggregateAndProof", AttestationSchema::Gloas) => {
            |v| de::<AggregateAndProof>(v)?.root(AttestationSchema::Gloas)
        }
        ("AggregateAndProof", AttestationSchema::Electra) => {
            |v| de::<AggregateAndProof>(v)?.root(AttestationSchema::Electra)
        }
        ("AggregateAndProof", AttestationSchema::Phase0) => {
            |v| de::<AggregateAndProof>(v)?.root(AttestationSchema::Phase0)
        }
        ("AttestationData", _) => |v| Ok(de::<AttestationData>(v)?.root()),
        ("BeaconBlockHeader", _) => |v| Ok(de::<BeaconBlockHeader>(v)?.root()),
        ("ExecutionPayload", _) => |v| de::<ExecutionPayload>(v)?.root(),
        ("ExecutionPayloadEnvelope", _) => |v| de::<ExecutionPayloadEnvelope>(v)?.root(),
        ("ExecutionRequests", _) => |v| Ok(de::<ExecutionRequests>(v)?.root()),
        ("PayloadAttestationData", _) => |v| Ok(de::<PayloadAttestationData>(v)?.root()),
        ("ProposerPreferences", _) => |v| Ok(de::<ProposerPreferences>(v)?.root()),
        ("Withdrawal", _) => |v| Ok(de::<Withdrawal>(v)?.root()),
        _ => panic!("no hasher for {fork}/{type_name}"),
    }
}

fn case_dirs(type_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for suite in std::fs::read_dir(type_dir).unwrap() {
        for case in std::fs::read_dir(suite.unwrap().path()).unwrap() {
            out.push(case.unwrap().path());
        }
    }
    out.sort();
    out
}

#[test]
fn consensus_ssz_static() {
    let Some(dir) = spec_dir() else { return };
    let mut total = 0;
    let mut forks: Vec<_> = std::fs::read_dir(dir.join("mainnet"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    forks.sort();
    for fork_dir in forks {
        let fork = fork_dir.file_name().unwrap().to_str().unwrap().to_string();
        let mut types: Vec<_> = std::fs::read_dir(fork_dir.join("ssz_static"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        types.sort();
        for type_dir in types {
            let type_name = type_dir.file_name().unwrap().to_str().unwrap().to_string();
            let h = hasher(&fork, &type_name);
            let cases = case_dirs(&type_dir);
            for case in &cases {
                let value: Value =
                    serde_json::from_slice(&std::fs::read(case.join("value.json")).unwrap())
                        .unwrap();
                let roots = std::fs::read_to_string(case.join("roots.yaml")).unwrap();
                let want = roots
                    .split('\'')
                    .find(|s| s.starts_with("0x"))
                    .unwrap_or_else(|| panic!("{}: no root in roots.yaml", case.display()));
                let got = h(value).unwrap_or_else(|e| panic!("{}: {e}", case.display()));
                assert_eq!(
                    format!("0x{}", hex::encode(got)),
                    want,
                    "{}",
                    case.display()
                );
            }
            eprintln!("{fork}/{type_name}: {} cases passed", cases.len());
            assert!(!cases.is_empty(), "{fork}/{type_name}: no cases");
            total += cases.len();
        }
    }
    eprintln!("ssz_static: {total} cases passed");
    assert!(total > 0);
}
