//! `trustlayer-verify` — independent, offline verification of TrustLayer
//! evidence bundles. No service, no database, no network.
//!
//! ```no_run
//! let bundle: serde_json::Value =
//!     serde_json::from_str(&std::fs::read_to_string("bundle.json").unwrap()).unwrap();
//! let report = trustlayer_verify::verify_bundle(&bundle);
//! assert!(report.verified);
//! ```

pub mod canonical;
pub mod did;
pub mod verify;

pub use canonical::{canonical_hash, canonical_json, sha256_hex};
pub use did::{base58_decode, resolve_ed25519_did};
pub use verify::{verified, verify_bundle, AnchorSummary, Check, Report, Status};
