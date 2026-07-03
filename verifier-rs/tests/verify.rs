use serde_json::{json, Value};
use trustlayer_verify::{canonical_hash, verify_bundle, Status};

fn sample() -> Value {
    serde_json::from_str(include_str!("../sample-bundle.json")).expect("valid sample bundle")
}

/// Re-seal a (tampered) bundle so its bundle_hash matches again — used to
/// isolate a single failing check from the outer integrity seal.
fn reseal(bundle: &mut Value) {
    let mut obj = bundle.as_object().unwrap().clone();
    obj.remove("bundle_hash");
    let hash = canonical_hash(&Value::Object(obj));
    bundle["bundle_hash"] = Value::String(hash);
}

#[test]
fn genuine_bundle_verifies_fully() {
    let report = verify_bundle(&sample());
    assert!(report.verified);
    for (name, check) in report.checks() {
        assert!(
            matches!(check.status, Status::Ok | Status::NotApplicable),
            "check {name} was {:?}",
            check.status
        );
    }
}

#[test]
fn reproduces_payload_and_bundle_hashes_independently() {
    let bundle = sample();
    assert_eq!(
        canonical_hash(&bundle["event"]["payload"]),
        bundle["event"]["payload_hash"].as_str().unwrap()
    );

    let mut obj = bundle.as_object().unwrap().clone();
    obj.remove("bundle_hash");
    assert_eq!(
        canonical_hash(&Value::Object(obj)),
        bundle["bundle_hash"].as_str().unwrap()
    );
}

#[test]
fn tampering_with_the_payload_is_detected() {
    let mut bundle = sample();
    bundle["event"]["payload"]["amount"] = json!(99999);
    let report = verify_bundle(&bundle);
    assert_eq!(report.payload_integrity.status, Status::Failed);
    assert!(!report.verified);
}

#[test]
fn tampering_with_any_bundle_field_breaks_the_seal() {
    let mut bundle = sample();
    bundle["event"]["action"] = Value::String("charge.refunded".into());
    let report = verify_bundle(&bundle);
    assert_eq!(report.bundle_integrity.status, Status::Failed);
    assert!(!report.verified);
}

#[test]
fn forged_signature_is_rejected_even_after_reseal() {
    let mut bundle = sample();
    let pv = bundle["event"]["identity"]["proof"]["proofValue"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = format!("{}{}", if pv.starts_with('0') { "1" } else { "0" }, &pv[1..]);
    bundle["event"]["identity"]["proof"]["proofValue"] = Value::String(flipped);
    reseal(&mut bundle);

    let report = verify_bundle(&bundle);
    assert_eq!(report.bundle_integrity.status, Status::Ok);
    assert_eq!(report.identity.status, Status::Failed);
    assert!(!report.verified);
}

#[test]
fn mismatched_delegation_is_rejected() {
    let mut bundle = sample();
    bundle["event"]["authority"]["subject"] =
        Value::String("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into());
    reseal(&mut bundle);

    let report = verify_bundle(&bundle);
    assert_eq!(report.delegation.status, Status::Failed);
    assert!(!report.verified);
}

#[test]
fn missing_identity_and_authority_are_not_applicable() {
    let mut bundle = sample();
    let event = bundle["event"].as_object_mut().unwrap();
    event.remove("identity");
    event.remove("authority");
    reseal(&mut bundle);

    let report = verify_bundle(&bundle);
    assert_eq!(report.identity.status, Status::NotApplicable);
    assert_eq!(report.authority.status, Status::NotApplicable);
    assert_eq!(report.delegation.status, Status::NotApplicable);
    assert!(report.verified);
}
