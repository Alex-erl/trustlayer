'use strict';

// trustlayer-verify — independent, offline verification of TrustLayer
// evidence bundles. No service, no database, no network.

const { canonicalJson, canonicalHash } = require('./lib/canonical');
const { base58Decode, resolveEd25519Did } = require('./lib/did');
const { verifyBundle, verified, verifyProof, withinScope } = require('./lib/verify');

module.exports = {
  verifyBundle,
  verified,
  verifyProof,
  withinScope,
  canonicalJson,
  canonicalHash,
  base58Decode,
  resolveEd25519Did,
};
