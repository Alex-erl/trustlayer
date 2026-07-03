# trustlayer-verify (Rust)

Independent, **offline** verification of TrustLayer evidence bundles — no
service, no database, no network. A second, fully independent implementation of
the [evidence bundle format](../SPEC.md), in Rust.

> The premise of TrustLayer is *don't trust the operator — verify the math.*
> This crate re-checks a bundle's cryptography from scratch and is byte-for-byte
> compatible with the JavaScript (`@trustlayer/verify`) and Elixir reference
> implementations — the same `bundle_hash`, the same `payload_hash`, the same
> Ed25519/`did:key` proofs, computed independently in three languages.

## CLI

```sh
cargo run -- ./evidence-bundle.json
# or, once installed:
trustlayer-verify ./evidence-bundle.json
```

Exit code `0` if every self-contained check passed, `1` if any failed, `2` on
bad input.

## Library

```rust
let data = std::fs::read_to_string("bundle.json")?;
let bundle: serde_json::Value = serde_json::from_str(&data)?;

let report = trustlayer_verify::verify_bundle(&bundle);
assert!(report.verified);

// recompute a hash yourself:
let h = trustlayer_verify::canonical_hash(&bundle["event"]["payload"]);
```

## What it checks (offline)

| Check | Meaning |
|---|---|
| `bundle_integrity` | Recomputes `bundle_hash` over the whole bundle (minus that field). |
| `payload_integrity` | Recomputes SHA-256 over the canonical JSON of `event.payload`. |
| `identity` | The agent credential's Ed25519 signature verifies against the `did:key` issuer. |
| `authority` | The mandate's signature verifies **and** the action stayed within scope. |
| `delegation` | Credential and mandate share one principal and reference the same agent. |

`identity`, `authority`, `delegation` report *not applicable* when the bundle
carries no credential/mandate. Anchors (Hedera, RFC 6962 log, RFC 3161 stamp)
are external online witnesses, listed for separate re-verification.

## Dependencies

Only `serde_json`, `sha2`, and `ed25519-dalek`. Base58 (`did:key`) and hex
decoding are implemented in-crate, small enough to audit.

## Compatibility

`sample-bundle.json` is the *same* fixture used by the JavaScript and Elixir
verifiers — a real bundle emitted by the reference service. `cargo test`
recomputes its hashes here and asserts they match the recorded values.

```sh
cargo test
```

## License

Apache-2.0.
