# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately by email to
**security@trustlayer.example** (replace with the project's real contact before
publishing). Do not open a public issue for a security report.

Include enough detail to reproduce: the affected component (spec, JS verifier,
…), a proof-of-concept bundle if applicable, and the impact you believe it has.
We aim to acknowledge within a few business days.

## What is in scope

This repository is the open verification core. The highest-severity class of bug
here is anything that makes the verifier **accept a bundle it should reject** —
for example:

- a canonicalization or hashing discrepancy that lets a tampered payload keep a
  valid-looking `payload_hash` or `bundle_hash`;
- an Ed25519 / `did:key` parsing flaw that accepts a forged or malleable
  signature, or resolves a DID to the wrong key;
- a scope-evaluation bug that reports an out-of-scope action as within scope.

A verifier that wrongly *rejects* a genuine bundle is also a bug, just a
lower-severity one.

## Cryptographic notes

- Signatures are Ed25519 (RFC 8032) over canonical JSON; verification uses the
  platform's audited crypto (`node:crypto` in the JS verifier).
- The offline verifier makes **no network calls** and reads only the bundle it
  is given. Anchor media (ledger, transparency log, timestamp authority) are
  re-verified separately, online, and are out of scope for the offline checks.
