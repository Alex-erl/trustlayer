//! Offline verification of a TrustLayer evidence bundle.
//!
//! Mirrors, check-for-check, the reference verifier in
//! `TrustLayer.Core.Evidence.Verifier` (Elixir) and `@trustlayer/verify` (JS):
//!
//! * `bundle_integrity`  — the export itself is intact (bundle_hash);
//! * `payload_integrity` — the recorded payload_hash matches the payload;
//! * `identity`          — the agent credential's Ed25519 signature verifies;
//! * `authority`         — the mandate's signature verifies and the action is in scope;
//! * `delegation`        — credential and mandate form one consistent chain.
//!
//! Anchors are external online witnesses, so they are *listed* for separate
//! re-verification rather than re-checked here.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use crate::canonical::{canonical_hash, canonical_json};
use crate::did::resolve_ed25519_did;

/// The outcome of a single check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Ok,
    Failed,
    NotApplicable,
}

/// A single named check with a human-readable detail.
#[derive(Debug, Clone)]
pub struct Check {
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn decide(pass: bool, ok_detail: &str, bad_detail: &str) -> Self {
        if pass {
            Check { status: Status::Ok, detail: ok_detail.to_string() }
        } else {
            Check { status: Status::Failed, detail: bad_detail.to_string() }
        }
    }

    fn failed(detail: &str) -> Self {
        Check { status: Status::Failed, detail: detail.to_string() }
    }

    fn not_applicable() -> Self {
        Check { status: Status::NotApplicable, detail: "not applicable".to_string() }
    }

    fn passed(&self) -> bool {
        matches!(self.status, Status::Ok | Status::NotApplicable)
    }
}

/// An anchor listed for online re-verification.
#[derive(Debug, Clone)]
pub struct AnchorSummary {
    pub adapter: String,
    pub medium: String,
    pub reference_present: bool,
}

/// The full verification report.
#[derive(Debug, Clone)]
pub struct Report {
    pub bundle_integrity: Check,
    pub payload_integrity: Check,
    pub identity: Check,
    pub authority: Check,
    pub delegation: Check,
    pub anchors: Vec<AnchorSummary>,
    pub verified: bool,
}

impl Report {
    /// The five checks, in display order, paired with their names.
    pub fn checks(&self) -> [(&'static str, &Check); 5] {
        [
            ("bundle_integrity", &self.bundle_integrity),
            ("payload_integrity", &self.payload_integrity),
            ("identity", &self.identity),
            ("authority", &self.authority),
            ("delegation", &self.delegation),
        ]
    }
}

/// Verify an evidence-bundle [`Value`]. Never panics on malformed input.
pub fn verify_bundle(bundle: &Value) -> Report {
    let empty = Map::new();
    let event = bundle.get("event").and_then(Value::as_object).unwrap_or(&empty);

    let bundle_integrity = check_bundle_integrity(bundle);
    let payload_integrity = check_payload_integrity(event);
    let identity = check_identity(event.get("identity"));
    let authority = check_authority(event.get("authority"), event.get("action"), event.get("payload"));
    let delegation = check_delegation(event.get("identity"), event.get("authority"));

    let anchors = event
        .get("anchors")
        .and_then(Value::as_array)
        .map(|list| list.iter().map(anchor_summary).collect())
        .unwrap_or_default();

    let verified = [&bundle_integrity, &payload_integrity, &identity, &authority, &delegation]
        .iter()
        .all(|check| check.passed());

    Report {
        bundle_integrity,
        payload_integrity,
        identity,
        authority,
        delegation,
        anchors,
        verified,
    }
}

/// Convenience: did every offline check pass?
pub fn verified(bundle: &Value) -> bool {
    verify_bundle(bundle).verified
}

fn check_bundle_integrity(bundle: &Value) -> Check {
    let Some(obj) = bundle.as_object() else {
        return Check::failed("bundle is not a JSON object");
    };
    let recorded = obj.get("bundle_hash").and_then(Value::as_str).unwrap_or("");
    let mut without_hash = obj.clone();
    without_hash.remove("bundle_hash");
    let recomputed = canonical_hash(&Value::Object(without_hash));
    Check::decide(
        recomputed == recorded,
        "bundle_hash matches the bundle contents",
        "the bundle has been altered since it was sealed",
    )
}

fn check_payload_integrity(event: &Map<String, Value>) -> Check {
    let recorded = event.get("payload_hash").and_then(Value::as_str).unwrap_or("");
    let payload = event.get("payload").cloned().unwrap_or(Value::Null);
    Check::decide(
        canonical_hash(&payload) == recorded,
        "payload_hash matches the payload",
        "the payload no longer matches its recorded hash",
    )
}

fn check_identity(credential: Option<&Value>) -> Check {
    match credential {
        None | Some(Value::Null) => Check::not_applicable(),
        Some(cred) => {
            let has_subject = cred.get("credentialSubject").is_some_and(Value::is_object);
            Check::decide(
                verify_proof(cred) && has_subject,
                "agent credential signature verifies",
                "credential signature does NOT verify",
            )
        }
    }
}

fn check_authority(mandate: Option<&Value>, action: Option<&Value>, payload: Option<&Value>) -> Check {
    match mandate {
        None | Some(Value::Null) => Check::not_applicable(),
        Some(mandate) => {
            if !verify_proof(mandate) {
                return Check::failed("mandate signature does NOT verify");
            }
            Check::decide(
                within_scope(mandate.get("scope"), action, payload),
                "mandate verifies and the action is in scope",
                "action is OUTSIDE the granted mandate scope",
            )
        }
    }
}

fn check_delegation(credential: Option<&Value>, mandate: Option<&Value>) -> Check {
    match (credential, mandate) {
        (Some(cred), Some(mandate)) if cred.is_object() && mandate.is_object() => {
            let same_issuer = cred.get("issuer") == mandate.get("issuer");
            let cred_subject = cred.get("credentialSubject").and_then(|s| s.get("id"));
            let same_subject = cred_subject.is_some() && cred_subject == mandate.get("subject");
            Check::decide(
                same_issuer && same_subject,
                "credential and mandate form one consistent chain",
                "credential and mandate do NOT match — broken chain",
            )
        }
        _ => Check::not_applicable(),
    }
}

/// Verify a document's `proof` the way `TrustLayer.Identity.Signing` signs it:
/// Ed25519 over the canonical JSON of the document without its `proof` member,
/// keyed by the `issuer` did:key.
fn verify_proof(doc: &Value) -> bool {
    let Some(obj) = doc.as_object() else { return false };
    let Some(issuer) = obj.get("issuer").and_then(Value::as_str) else { return false };
    let Some(proof) = obj.get("proof").and_then(Value::as_object) else { return false };
    let Some(proof_value) = proof.get("proofValue").and_then(Value::as_str) else { return false };

    let Some(signature_bytes) = hex_to_bytes(proof_value) else { return false };
    let Ok(signature_bytes) = <[u8; 64]>::try_from(signature_bytes) else { return false };
    let Some(public_key) = resolve_ed25519_did(issuer) else { return false };

    let mut unsigned = obj.clone();
    unsigned.remove("proof");
    let message = canonical_json(&Value::Object(unsigned));

    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else { return false };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key.verify_strict(message.as_bytes(), &signature).is_ok()
}

/// Mirrors `Mandate.within_scope?/3`.
fn within_scope(scope: Option<&Value>, action: Option<&Value>, payload: Option<&Value>) -> bool {
    let (Some(scope), Some(payload)) = (
        scope.and_then(Value::as_object),
        payload.and_then(Value::as_object),
    ) else {
        return false;
    };

    let action_ok = match scope.get("action") {
        None | Some(Value::Null) => true,
        scoped => scoped == action,
    };

    let amount_ok = match scope.get("max_amount") {
        None | Some(Value::Null) => true,
        Some(max) => match (max.as_f64(), payload.get("amount").and_then(Value::as_f64)) {
            (Some(max), Some(amount)) => amount <= max,
            _ => false,
        },
    };

    let currency = payload.get("currency").or_else(|| payload.get("ccy"));
    let currency_ok = match scope.get("currency") {
        None | Some(Value::Null) => true,
        scoped => scoped == currency,
    };

    action_ok && amount_ok && currency_ok
}

fn anchor_summary(anchor: &Value) -> AnchorSummary {
    let adapter = anchor.get("adapter").and_then(Value::as_str).unwrap_or("").to_string();
    let reference_present = anchor.get("reference").is_some();
    let medium = medium(&adapter).to_string();
    AnchorSummary { adapter, medium, reference_present }
}

fn medium(adapter: &str) -> &str {
    match adapter {
        "hedera-hcs" => "Hedera Consensus Service (re-verify via a mirror node)",
        "hedera-mock" => "simulated ledger (re-verify via the mock mirror)",
        "internal-notary" => "internal notary signature",
        "transparency-log" => "RFC 6962 transparency log (inclusion proof + signed tree head)",
        "eidas-rfc3161" => "RFC 3161 timestamp token (self-contained; verify the CMS signature + imprint)",
        other => other,
    }
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
