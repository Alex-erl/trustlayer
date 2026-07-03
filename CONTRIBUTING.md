# Contributing

Thanks for your interest in TrustLayer's open verification core.

## Scope of this repository

This repo is the **open, standards-based** part of TrustLayer: the evidence
bundle format ([`SPEC.md`](./SPEC.md)) and reference verifiers. The most
valuable contributions here are:

- **New-language verifiers** (Rust, Go, Python, a browser/Web Crypto build)
  that pass the shared compatibility fixtures.
- **Spec clarifications** — anywhere the format is ambiguous enough that two
  implementers could diverge.
- **Interoperability** with the wider ecosystem (EUDI Wallet / EBSI, other VC
  and DID tooling).

## Ground rules

- Every verifier MUST verify the shared `sample-bundle.json` and MUST reproduce
  its `bundle_hash` and `payload_hash` exactly. Byte-compatibility across
  languages is the whole point — a change that breaks it is a bug.
- Changes to canonicalization, hashing, the proof scheme, or the offline checks
  are **spec changes**: open an issue first, and they bump the format version
  (see `SPEC.md` §6).
- Keep the JS verifier dependency-free (built-ins only). Verifiers should be
  small enough to audit in one sitting.

## Development

```sh
cd verifier-js
npm test
```

## Sign-off & licensing

Contributions are accepted under the repository's Apache-2.0 license. By opening
a pull request you certify you have the right to submit the work under that
license (Developer Certificate of Origin).

## Security

Do not open public issues for vulnerabilities — see [`SECURITY.md`](./SECURITY.md).
