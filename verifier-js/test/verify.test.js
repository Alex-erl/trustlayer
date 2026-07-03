'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const { verifyBundle, canonicalHash } = require('..');

const SAMPLE_PATH = join(__dirname, '..', 'sample-bundle.json');
const sample = () => JSON.parse(readFileSync(SAMPLE_PATH, 'utf8'));

// Re-seal a (tampered) bundle so its bundle_hash matches its contents again —
// used to isolate a single failing check from the outer integrity seal.
function reseal(bundle) {
  const { bundle_hash, ...rest } = bundle;
  bundle.bundle_hash = canonicalHash(rest);
  return bundle;
}

test('a genuine bundle verifies fully offline', () => {
  const report = verifyBundle(sample());
  assert.equal(report.verified, true);
  for (const [name, check] of Object.entries(report.checks)) {
    assert.ok(
      check.status === 'ok' || check.status === 'not_applicable',
      `check ${name} was ${check.status}`,
    );
  }
});

test('canonical hashing reproduces payload_hash and bundle_hash independently', () => {
  const bundle = sample();
  assert.equal(canonicalHash(bundle.event.payload), bundle.event.payload_hash);

  const { bundle_hash, ...rest } = bundle;
  assert.equal(canonicalHash(rest), bundle_hash);
});

test('the offline checks are present and reflect the sample', () => {
  const report = verifyBundle(sample());
  assert.equal(report.checks.payload_integrity.status, 'ok');
  assert.equal(report.checks.identity.status, 'ok');
  assert.equal(report.checks.authority.status, 'ok');
  assert.equal(report.checks.delegation.status, 'ok');
  assert.deepEqual(
    report.anchors.map((a) => a.adapter).sort(),
    ['hedera-mock', 'internal-notary', 'transparency-log'],
  );
});

test('tampering with the payload is detected', () => {
  const bundle = sample();
  bundle.event.payload.amount = 999999;
  const report = verifyBundle(bundle);
  assert.equal(report.checks.payload_integrity.status, 'failed');
  assert.equal(report.verified, false);
});

test('tampering with any bundle field breaks the seal', () => {
  const bundle = sample();
  bundle.event.action = 'charge.refunded';
  const report = verifyBundle(bundle);
  assert.equal(report.checks.bundle_integrity.status, 'failed');
  assert.equal(report.verified, false);
});

test('a forged credential signature is rejected even if the seal is repaired', () => {
  const bundle = sample();
  const pv = bundle.event.identity.proof.proofValue;
  // flip the first byte of the signature, then re-seal so bundle_integrity passes
  bundle.event.identity.proof.proofValue = (pv[0] === '0' ? '1' : '0') + pv.slice(1);
  reseal(bundle);

  const report = verifyBundle(bundle);
  assert.equal(report.checks.bundle_integrity.status, 'ok');
  assert.equal(report.checks.identity.status, 'failed');
  assert.equal(report.verified, false);
});

test('a mismatched delegation chain is rejected', () => {
  const bundle = sample();
  // point the mandate at a different agent than the credential subject
  bundle.event.authority.subject = 'did:key:z6MkDIFFERENTagentDIFFERENTagentDIFFERENT00';
  reseal(bundle);

  const report = verifyBundle(bundle);
  assert.equal(report.checks.delegation.status, 'failed');
  assert.equal(report.verified, false);
});

test('a bundle with no identity/authority is not failed on those checks', () => {
  const bundle = sample();
  delete bundle.event.identity;
  delete bundle.event.authority;
  reseal(bundle);

  const report = verifyBundle(bundle);
  assert.equal(report.checks.identity.status, 'not_applicable');
  assert.equal(report.checks.authority.status, 'not_applicable');
  assert.equal(report.checks.delegation.status, 'not_applicable');
  assert.equal(report.verified, true);
});
