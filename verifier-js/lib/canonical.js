'use strict';

// Canonical JSON + SHA-256, byte-for-byte compatible with the Elixir
// `TrustLayer.Crypto` module. This is the foundation of independent
// verification: the same logical value hashes identically on any machine,
// in any language.
//
//   * objects  -> keys sorted lexicographically by their UTF-8 bytes, recursively
//   * arrays   -> element order preserved
//   * scalars  -> standard JSON encoding (JSON.stringify)
//
// The byte-wise key ordering matches Erlang/Elixir binary comparison exactly,
// so it stays correct even for non-ASCII keys (JavaScript's default string
// sort compares UTF-16 code units, which would diverge there).

const { createHash } = require('node:crypto');

function canonicalJson(value) {
  return encode(value);
}

function encode(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('non-finite numbers are not JSON-encodable');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object':
      return Array.isArray(value) ? encodeArray(value) : encodeObject(value);
    default:
      throw new Error(`unsupported value type: ${typeof value}`);
  }
}

function encodeArray(arr) {
  return '[' + arr.map(encode).join(',') + ']';
}

function encodeObject(obj) {
  const keys = Object.keys(obj).sort(byteCompare);
  const members = keys.map((k) => JSON.stringify(k) + ':' + encode(obj[k]));
  return '{' + members.join(',') + '}';
}

// Compare two strings by their UTF-8 byte sequences (== Erlang binary order).
function byteCompare(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

// Lowercase hex SHA-256 of the canonical JSON of `value`.
// Equivalent to `TrustLayer.Crypto.hash/1`.
function canonicalHash(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

module.exports = { canonicalJson, canonicalHash };
