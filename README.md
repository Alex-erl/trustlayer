# TrustLayer — open verification core

**Verifiable accountability for AI agents.** When an AI agent acts on someone's
behalf — moves money, signs, decides — TrustLayer produces a tamper-evident,
independently verifiable record of *who* the agent is, *what it was authorized to
do*, and *what it actually did*.

This repository holds the **open, standards-based parts** of TrustLayer: the
evidence-bundle format, its specification, and reference verifiers. They are
open source on purpose — the product's core promise is *don't trust the operator,
verify the math*, and that promise is only credible if the verification is open
and anyone can re-implement it.

## What's here

| Path | What it is | License |
|---|---|---|
| [`SPEC.md`](./SPEC.md) | The Evidence Bundle format + verification algorithm, language-neutral. | Apache-2.0 |
| [`verifier-js/`](./verifier-js) | `@trustlayer/verify` — offline verifier + CLI (Node.js, zero deps). | Apache-2.0 |

Planned: a Rust verifier, and a browser (Web Crypto) build of the JS verifier.

## Try it

```sh
cd verifier-js
npm test                       # cross-language byte-compatibility tests
node bin/cli.js sample-bundle.json
```

`sample-bundle.json` is a real bundle produced by the (Elixir) reference
service; the tests recompute its hashes here and confirm they match — proving the
format is verifiable independently of the implementation that wrote it.

## The bigger picture

TrustLayer as a product follows an **open-core** model: this verification core
and the client libraries are open (Apache-2.0); the server and the managed
service are covered separately. See [`../OPEN-CORE.md`](../OPEN-CORE.md).

## Standards

W3C Verifiable Credentials & `did:key` · JSON Canonicalization (RFC 8785) ·
Ed25519 (RFC 8032) · RFC 6962 transparency logs · RFC 3161 timestamps ·
aligned with eIDAS 2 / EUDI and EU AI Act Art. 12 record-keeping.

## Contributing & security

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`SECURITY.md`](./SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
