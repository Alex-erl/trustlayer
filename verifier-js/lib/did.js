'use strict';

// Minimal `did:key` resolution for Ed25519 keys (W3C did:key method).
// A did:key is self-contained — the public key *is* the identifier:
//
//   did:key:z<base58btc( 0xED 0x01 || <32-byte ed25519 pubkey> )>
//
// so resolving one needs no network and no registry.

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const B58_INDEX = new Map();
for (let i = 0; i < B58_ALPHABET.length; i++) B58_INDEX.set(B58_ALPHABET[i], i);

function base58Decode(str) {
  let leadingOnes = 0;
  while (leadingOnes < str.length && str[leadingOnes] === '1') leadingOnes++;

  let num = 0n;
  for (const ch of str) {
    const v = B58_INDEX.get(ch);
    if (v === undefined) throw new Error(`invalid base58 character: ${JSON.stringify(ch)}`);
    num = num * 58n + BigInt(v);
  }

  const body = [];
  while (num > 0n) {
    body.unshift(Number(num & 0xffn));
    num >>= 8n;
  }

  return Buffer.concat([Buffer.alloc(leadingOnes, 0), Buffer.from(body)]);
}

const DID_KEY_PREFIX = 'did:key:z';
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);

// Resolve an Ed25519 did:key to its 32-byte raw public key (Buffer).
// Throws on anything that is not a well-formed Ed25519 did:key.
function resolveEd25519Did(did) {
  if (typeof did !== 'string' || !did.startsWith(DID_KEY_PREFIX)) {
    throw new Error('not an Ed25519 did:key');
  }

  const decoded = base58Decode(did.slice(DID_KEY_PREFIX.length));
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(ED25519_MULTICODEC)) {
    throw new Error('unsupported did:key multicodec (expected ed25519-pub)');
  }

  return decoded.subarray(2);
}

module.exports = { base58Decode, resolveEd25519Did, DID_KEY_PREFIX };
