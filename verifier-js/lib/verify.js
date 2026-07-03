'use strict';

// Offline verification of a TrustLayer evidence bundle.
//
// This mirrors, check-for-check, the reference verifier in
// `TrustLayer.Core.Evidence.Verifier` — but in the browser/Node runtime, with
// no service, no database and no network. It re-checks everything that is
// self-contained:
//
//   * bundle_integrity  — the export itself is intact (bundle_hash);
//   * payload_integrity — the recorded payload_hash matches the payload;
//   * identity          — the agent credential's Ed25519 signature verifies;
//   * authority         — the mandate's signature verifies and the action is in scope;
//   * delegation        — credential and mandate form one consistent chain.
//
// Anchors are external witnesses on online media (a ledger, a log), so they are
// *listed* with their medium for separate online re-verification rather than
// re-checked here. `verified` reflects the offline, self-contained checks.

const { createPublicKey, verify: edVerify } = require('node:crypto');
const { canonicalJson, canonicalHash } = require('./canonical');
const { resolveEd25519Did } = require('./did');

function verifyBundle(bundle) {
  if (!isObject(bundle)) throw new TypeError('bundle must be a JSON object');

  const event = isObject(bundle.event) ? bundle.event : {};

  const checks = {
    bundle_integrity: checkBundleIntegrity(bundle),
    payload_integrity: checkPayloadIntegrity(event),
    identity: checkIdentity(event.identity),
    authority: checkAuthority(event.authority, event.action, event.payload),
    delegation: checkDelegation(event.identity, event.authority),
  };

  return {
    checks,
    anchors: Array.isArray(event.anchors) ? event.anchors.map(anchorSummary) : [],
    verified: Object.values(checks).every(passed),
  };
}

function verified(bundle) {
  return verifyBundle(bundle).verified;
}

// --- individual checks ------------------------------------------------------

function checkBundleIntegrity(bundle) {
  const { bundle_hash, ...rest } = bundle;
  return ok(canonicalHash(rest) === bundle_hash, 'bundle_hash matches the bundle contents');
}

function checkPayloadIntegrity(event) {
  const payload = event.payload === undefined ? null : event.payload;
  return ok(canonicalHash(payload) === event.payload_hash, 'payload_hash matches the payload');
}

function checkIdentity(credential) {
  if (credential == null) return na();
  const good = verifyProof(credential) && isObject(credential.credentialSubject);
  return ok(good, good ? 'agent credential signature verifies' : 'credential invalid');
}

function checkAuthority(mandate, action, payload) {
  if (mandate == null) return na();
  if (!verifyProof(mandate)) return ok(false, 'mandate invalid: signature does not verify');
  const scope = isObject(mandate.scope) ? mandate.scope : {};
  return ok(withinScope(scope, action, payload), 'mandate verifies and the action is in scope');
}

function checkDelegation(credential, mandate) {
  if (!isObject(credential) || !isObject(mandate)) return na();
  const consistent =
    credential.issuer === mandate.issuer &&
    isObject(credential.credentialSubject) &&
    credential.credentialSubject.id === mandate.subject;
  return ok(consistent, 'credential and mandate form a consistent delegation');
}

// --- Ed25519 linked-data proof ----------------------------------------------

// Verify a document's `proof` the same way `TrustLayer.Identity.Signing` signs it:
// Ed25519 over the canonical JSON of the document *without* its `proof` member,
// using the public key resolved from the document's `issuer` did:key.
function verifyProof(doc) {
  if (!isObject(doc) || !isObject(doc.proof) || typeof doc.issuer !== 'string') return false;

  const proofValue = doc.proof.proofValue;
  if (typeof proofValue !== 'string' || proofValue.length % 2 !== 0 || !/^[0-9a-f]*$/.test(proofValue)) {
    return false;
  }

  let publicKey;
  let signature;
  try {
    publicKey = resolveEd25519Did(doc.issuer);
    signature = Buffer.from(proofValue, 'hex');
  } catch {
    return false;
  }

  const { proof, ...unsigned } = doc;
  const message = Buffer.from(canonicalJson(unsigned), 'utf8');

  try {
    const key = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: publicKey.toString('base64url') },
      format: 'jwk',
    });
    return edVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

// --- scope evaluation (mirrors Mandate.within_scope?/3) ---------------------

function withinScope(scope, action, payload) {
  if (!isObject(scope) || !isObject(payload)) return false;
  const actionOk = scope.action == null || scope.action === action;
  const amountOk = amountWithin(scope.max_amount, payload.amount);
  const currency = payload.currency ?? payload.ccy;
  const currencyOk = scope.currency == null || scope.currency === currency;
  return actionOk && amountOk && currencyOk;
}

function amountWithin(max, amount) {
  if (max == null) return true;
  if (typeof max === 'number' && typeof amount === 'number') return amount <= max;
  return false;
}

// --- anchors ----------------------------------------------------------------

function anchorSummary(anchor) {
  const adapter = isObject(anchor) ? anchor.adapter : undefined;
  return {
    adapter,
    medium: medium(adapter),
    reference_present: isObject(anchor) && Object.prototype.hasOwnProperty.call(anchor, 'reference'),
  };
}

const MEDIA = {
  'hedera-hcs': 'Hedera Consensus Service (re-verify via a mirror node)',
  'hedera-mock': 'simulated ledger (re-verify via the mock mirror)',
  'internal-notary': 'internal notary signature',
  'transparency-log': 'RFC 6962 transparency log (inclusion proof + signed tree head)',
  'eidas-rfc3161': 'RFC 3161 timestamp token (self-contained; verify the CMS signature + imprint)',
};

function medium(adapter) {
  return MEDIA[adapter] || adapter;
}

// --- helpers ----------------------------------------------------------------

function ok(bool, detail) {
  return { status: bool ? 'ok' : 'failed', detail };
}

function na() {
  return { status: 'not_applicable' };
}

function passed(check) {
  return check.status === 'ok' || check.status === 'not_applicable';
}

function isObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

module.exports = { verifyBundle, verified, verifyProof, withinScope };
