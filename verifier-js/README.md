# @trustlayer/verify

Independent, **offline** verification of TrustLayer evidence bundles — no
service, no database, no network. Point it at an exported bundle and it
re-checks the cryptography itself.

> The whole premise of TrustLayer is *don't trust the operator — verify the
> math.* That only holds if the verifier is open and anyone can re-implement it.
> This is that verifier, in JavaScript. It is byte-for-byte compatible with the
> reference implementation in Elixir.

## Install

```sh
npm install @trustlayer/verify
```

Zero runtime dependencies. Works on Node.js ≥ 18 (uses only the built-in
`node:crypto`).

## CLI

```sh
npx trustlayer-verify ./evidence-bundle.json
```

Exit code `0` if every self-contained check passed, `1` if any failed.

## Library

```js
const { verifyBundle, canonicalHash } = require('@trustlayer/verify');

const report = verifyBundle(bundle);
report.verified;          // => true | false
report.checks.identity;   // => { status: 'ok', detail: '...' }

// recompute a payload hash yourself, in one line:
canonicalHash({ amount: 4200, currency: 'EUR' });
// => '…' (lowercase hex SHA-256 of the canonical JSON)
```

## What it checks (offline)

| Check | Meaning |
|---|---|
| `bundle_integrity` | Recomputes `bundle_hash` over the whole bundle (minus that field) — the export has not been altered. |
| `payload_integrity` | Recomputes SHA-256 over the canonical JSON of `event.payload`; it must equal `event.payload_hash`. |
| `identity` | The agent credential's Ed25519 signature verifies against the `did:key` issuer. |
| `authority` | The mandate's signature verifies **and** the recorded action stayed within its scope. |
| `delegation` | Credential and mandate share one issuing principal and reference the same agent. |

`identity`, `authority` and `delegation` report `not_applicable` when the bundle
carries no credential/mandate — that does not fail a bundle.

**Anchors** (Hedera, an RFC 6962 transparency log, an RFC 3161 timestamp) are
external witnesses on online media, so they are *listed* with their medium for
separate online re-verification rather than re-checked here. `verified` reflects
the offline, self-contained checks — enough to trust a record's integrity and
provenance on your own.

## How compatibility is guaranteed

`sample-bundle.json` is a real bundle produced by the Elixir reference
implementation. The test suite recomputes its `bundle_hash` and `payload_hash`
here in JavaScript and asserts they match the values the Elixir side wrote — so
the canonical-JSON encoder, the hash, and the Ed25519 proof scheme are all
verified to agree across languages.

```sh
npm test
```

## The bundle format

See [`../SPEC.md`](../SPEC.md) for the full, language-neutral specification —
enough to write a verifier in any language.

## License

Apache-2.0.
