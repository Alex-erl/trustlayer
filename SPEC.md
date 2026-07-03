# TrustLayer Evidence Bundle — Format Specification

**Version 1.0 · status: draft · license: Apache-2.0**

An *evidence bundle* is a self-contained, tamper-evident JSON document that
records a single action taken by an AI agent, together with everything needed to
verify — offline, with no access to the issuing service — that the record is
intact, authentic, and authorized.

This document specifies the format and the verification algorithm precisely
enough to implement an independent verifier in any language. The reference
implementations are [`@trustlayer/verify`](./verifier-js) (JavaScript) and
`TrustLayer.Core.Evidence.Verifier` (Elixir); both are tested against the same
bundle and agree byte-for-byte.

## 1. Canonical JSON

All hashing and signing is done over **canonical JSON**, defined as:

1. **Objects** — members are serialized in ascending order of their keys, where
   keys are compared as sequences of **UTF-8 bytes** (lexicographic). Applied
   recursively.
2. **Arrays** — element order is preserved.
3. **Strings** — standard JSON string encoding (RFC 8259): `"`, `\` and the
   control characters `U+0000`–`U+001F` are escaped; all other characters,
   including non-ASCII and `/`, are emitted literally as UTF-8.
4. **Numbers** — standard JSON number encoding. Bundles SHOULD use integers for
   hashed fields to avoid floating-point representation ambiguity.
5. **`true` / `false` / `null`** — literal.
6. No insignificant whitespace anywhere.

This is JCS-compatible (RFC 8785) for the value space used by bundles. The
canonical form of a value is a byte string; its UTF-8 bytes are what gets hashed
or signed.

> Example: `{"b":1,"a":{"d":2,"c":3}}` canonicalizes to `{"a":{"c":3,"d":2},"b":1}`.

## 2. Hashing

`hash(value)` = lowercase hex-encoded `SHA-256` of the UTF-8 bytes of the
canonical JSON of `value`.

## 3. Ed25519 proofs (`did:key`)

Credentials and mandates are signed JSON documents. The signer's identity is a
`did:key`:

```
did:key:z<base58btc( 0xED 0x01 || <32-byte ed25519 public key> )>
```

- `z` is the multibase prefix for base58btc.
- `0xED 0x01` is the multicodec varint for `ed25519-pub`.

To resolve a `did:key` to a public key: strip the `did:key:z` prefix,
base58btc-decode the remainder, assert the first two bytes are `0xED 0x01`, and
take the following 32 bytes.

A **proof** is attached as:

```json
"proof": {
  "type": "Ed25519Signature2020",
  "verificationMethod": "<issuer-did>#key-1",
  "proofValue": "<lowercase hex Ed25519 signature>"
}
```

The signature is computed over the UTF-8 bytes of `canonical_json(document
without its "proof" member)`, using the private key of the DID in the
document's `issuer` field. Verification resolves `issuer` to a public key and
checks the signature over the same bytes.

## 4. Bundle structure

```jsonc
{
  "bundle_version": "1.0",
  "generated_at": "<ISO 8601 UTC>",
  "event": {
    "id": "<uuid>",
    "agent_id": "<string>",
    "action": "<string>",
    "payload": { /* arbitrary JSON object */ },
    "payload_hash": "<hash(payload)>",
    "created_at": "<ISO 8601 UTC>",
    "org_id": "<string|null>",
    "anchors": [ /* see §4.1 */ ],
    "identity": { /* optional Verifiable Credential, §4.2 */ },
    "authority": { /* optional authorization mandate, §4.3 */ }
  },
  "proof": { /* the service's live re-verification report; informational */ },
  "retention": { "policy_days": 365, "retain_until": "<ISO 8601 UTC>" },
  "verification_instructions": [ "human-readable steps" ],
  "bundle_hash": "<hash(bundle without bundle_hash)>"
}
```

`bundle_hash` seals the entire bundle: it is `hash(bundle)` computed over the
bundle object with the `bundle_hash` member removed.

### 4.1 Anchors

Each anchor records that `payload_hash` was witnessed by an independent medium:

```json
{ "adapter": "hedera-hcs", "anchored_at": "<ISO 8601>", "reference": { /* medium-specific */ } }
```

Known adapters: `hedera-hcs`, `hedera-mock`, `internal-notary`,
`transparency-log` (RFC 6962), `eidas-rfc3161` (RFC 3161). Anchors are external
online witnesses; they are re-verified on their own medium, not by the offline
verifier (§5).

### 4.2 `identity` — Agent Control Credential

A W3C-style Verifiable Credential binding an agent (`credentialSubject.id`, a
`did:key`) to a controller. Signed by the controller's `did:key` (§3).

### 4.3 `authority` — Intent Mandate

A signed statement granting the agent (`subject`) authority within a `scope`:

```json
{ "action": "charge.created", "max_amount": 5000, "currency": "EUR" }
```

An action is **within scope** when: `scope.action` is absent or equals the
event action; `scope.max_amount` is absent or `payload.amount ≤ max_amount`;
`scope.currency` is absent or equals `payload.currency` (or `payload.ccy`).

## 5. Offline verification algorithm

A conforming verifier, given only the bundle JSON, MUST evaluate:

| Check | Passes when |
|---|---|
| `bundle_integrity` | `hash(bundle without bundle_hash) == bundle.bundle_hash` |
| `payload_integrity` | `hash(event.payload) == event.payload_hash` |
| `identity` | present ⇒ the credential's proof verifies (§3) and it has a `credentialSubject` |
| `authority` | present ⇒ the mandate's proof verifies **and** the action is within scope (§4.3) |
| `delegation` | both present ⇒ `credential.issuer == mandate.issuer` and `credential.credentialSubject.id == mandate.subject` |

`identity`, `authority`, `delegation` are **not applicable** (and do not fail the
bundle) when the referenced document is absent. The bundle is `verified` when
every check is `ok` or `not_applicable`.

Anchors are reported for separate online re-verification and do not affect the
offline `verified` result.

## 6. Versioning

`bundle_version` is `"1.0"`. Backwards-incompatible changes to canonicalization,
hashing, the proof scheme, or the checks in §5 increment the major version.
