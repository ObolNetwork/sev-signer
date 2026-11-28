//! Web3Signer 26.9.0's OpenAPI request examples for the Gloas types
//! (`tests/vectors/web3signer-gloas-examples.json`: Consensys/web3signer,
//! openapi-specs/eth2/signing/paths/sign.yaml at tag 26.9.0, Apache-2.0).
//!
//! Every example must parse with our request types. BLOCK_V2 (GLOAS) and
//! AGGREGATE_AND_PROOF_V2 (GLOAS) carry a `signingRoot`, which must equal
//! ours (for the aggregate, an independent check of the progressive Gloas
//! `Attestation`). The other five examples carry no root upstream; the
//! go-eth2-client vectors and the consensus spec tests cover those.
//!
//! The EXECUTION_PAYLOAD_ENVELOPE example's `logs_bloom` is 262 bytes
//! upstream (it must be 256); the test checks that it is rejected and uses a
//! corrected copy.

use dvtee::network::Network;
use dvtee::signing::{self, Policy, PrepareError, SignBody, SignRequest};
use serde_json::Value;

/// The examples' chain: genesis validators root 0x0470...a673 with every fork
/// at epoch 0 and every fork version 0x00000001, as their fork_info says.
fn example_network(gvr: &str) -> Network {
    let mut cfg = String::from("PRESET_BASE: mainnet\nGENESIS_FORK_VERSION: 0x00000001\n");
    for fork in [
        "ALTAIR",
        "BELLATRIX",
        "CAPELLA",
        "DENEB",
        "ELECTRA",
        "FULU",
        "GLOAS",
    ] {
        cfg += &format!("{fork}_FORK_VERSION: 0x00000001\n{fork}_FORK_EPOCH: 0\n");
    }
    Network::from_config_yaml(&cfg, dvtee::network::parse_root(gvr).unwrap()).unwrap()
}

#[test]
fn gloas_examples() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/web3signer-gloas-examples.json");
    let file: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let examples = file["examples"].as_object().unwrap();
    assert_eq!(examples.len(), 7);
    let net = example_network("0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673");

    let mut signed = Vec::new();
    let mut matched = Vec::new();
    for (name, example) in examples {
        let mut example = example.clone();
        if name == "EXECUTION_PAYLOAD_ENVELOPE (GLOAS)" {
            // Upstream bug: logs_bloom is 262 bytes, not 256. It must be
            // rejected as is, and parse once corrected.
            let err = serde_json::from_value::<SignRequest>(example.clone()).unwrap_err();
            assert!(
                err.to_string().contains("expected 256 bytes, got 262"),
                "{err}"
            );
            let bloom = example
                .pointer_mut("/execution_payload_envelope/data/payload/logs_bloom")
                .unwrap();
            *bloom = Value::String(format!("0x{}", "00".repeat(256)));
        }
        let example = &example;
        let req: SignRequest = serde_json::from_value(example.clone())
            .unwrap_or_else(|e| panic!("{name}: does not parse: {e}"));
        let provided = example.get("signingRoot").cloned();
        let mut body = example.clone();
        body.as_object_mut().unwrap().remove("signingRoot");
        let unchecked: SignRequest = serde_json::from_value(body).unwrap();
        let result = signing::prepare(&unchecked, &net, &Policy::default());

        match &req.body {
            SignBody::ExecutionPayloadBid {} => {
                assert!(matches!(result, Err(PrepareError::Refused(_))), "{name}");
            }
            SignBody::ExecutionPayloadEnvelope {
                execution_payload_envelope: e,
                ..
            } => {
                // builder_index 1: an external builder's envelope, refused.
                // Its root is still computable.
                assert!(matches!(result, Err(PrepareError::Refused(_))), "{name}");
                assert_eq!(e.version, "GLOAS");
                e.data.root().unwrap();
            }
            _ => {
                let p = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                let computed = format!("0x{}", hex::encode(p.signing_root));
                if let Some(provided) = provided {
                    assert_eq!(provided.as_str().unwrap(), computed, "{name}");
                    signing::prepare(&req, &net, &Policy::default()).unwrap();
                    matched.push(name.as_str());
                }
                signed.push(p.kind);
            }
        }
    }
    matched.sort();
    assert_eq!(
        matched,
        ["AGGREGATE_AND_PROOF_V2 (GLOAS)", "BLOCK_V2 (GLOAS)"]
    );
    signed.sort();
    assert_eq!(
        signed,
        [
            "AGGREGATE_AND_PROOF_V2",
            "BLOCK_V2",
            "BUILDER_REQUEST_AUTH",
            "PAYLOAD_ATTESTATION_MESSAGE",
            "PROPOSER_PREFERENCES"
        ]
    );
}
