//! Minimal `did:key` resolution for Ed25519 keys.
//!
//! A did:key is self-contained — the public key *is* the identifier:
//!
//! ```text
//! did:key:z<base58btc( 0xED 0x01 || <32-byte ed25519 pubkey> )>
//! ```

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a base58btc (Bitcoin alphabet) string. Returns `None` on any
/// character outside the alphabet.
pub fn base58_decode(input: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();

    for ch in input.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == ch)? as u32;
        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // leading '1's encode leading zero bytes
    for ch in input.bytes() {
        if ch == b'1' {
            bytes.insert(0, 0);
        } else {
            break;
        }
    }

    Some(bytes)
}

const DID_KEY_PREFIX: &str = "did:key:z";
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Resolve an Ed25519 `did:key` to its 32-byte raw public key.
pub fn resolve_ed25519_did(did: &str) -> Option<[u8; 32]> {
    let b58 = did.strip_prefix(DID_KEY_PREFIX)?;
    let decoded = base58_decode(b58)?;
    if decoded.len() != 34 || decoded[0..2] != ED25519_MULTICODEC {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..34]);
    Some(key)
}
