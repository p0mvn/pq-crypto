//! FIPS 205 WOTS+ (section 5): the one-time keys at the leaves of every XMSS tree.
//!
//! The message digits and checksum are the ones the RFC 8391 [`crate::wots`] module
//! computes; FIPS 205 Algorithm 4 with its left-shifted checksum gives the same 67
//! digits. The chain steps differ: each step is F over the public seed and an
//! address, without RFC 8391's per-step keys and masks.

use zeroize::Zeroizing;

use crate::digest::MessageDigest;
use crate::fips205_address::compress;
use crate::hash::fips205;
use crate::params::ELEMENT_BYTES;
use crate::seed::{PublicSeed, SecretSeed};
use crate::slh_dsa::address::{
    AddressError, TreePosition, wots_hash_address, wots_public_key_address, wots_secret_address,
};
use crate::wots::{BASE16_MAX, CHAINS, message_digits};

/// One revealed value per chain, in chain order.
pub(crate) type WotsSignature = [[u8; ELEMENT_BYTES]; CHAINS];

/// FIPS 205 Algorithm 6: runs every chain of the key at `key_pair` from its secret
/// start to its end, then compresses the 67 ends into the public key.
pub(crate) fn public_key(
    secret_seed: &SecretSeed,
    public_seed: &PublicSeed,
    tree: TreePosition,
    key_pair: u32,
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    let mut ends = [[0u8; ELEMENT_BYTES]; CHAINS];
    for (chain_index, end) in (0u32..).zip(ends.iter_mut()) {
        let start = secret_start(secret_seed, public_seed, tree, key_pair, chain_index)?;
        *end = chain(
            public_seed,
            tree,
            key_pair,
            chain_index,
            &start,
            0,
            BASE16_MAX,
        )?;
    }

    compress_ends(public_seed, tree, key_pair, &ends)
}

/// FIPS 205 Algorithm 7: reveals each chain of the key at `key_pair` at the position
/// its digit of `message` selects.
pub(crate) fn sign(
    message: &[u8; ELEMENT_BYTES],
    secret_seed: &SecretSeed,
    public_seed: &PublicSeed,
    tree: TreePosition,
    key_pair: u32,
) -> Result<WotsSignature, AddressError> {
    let digits = message_digits(&MessageDigest::from_bytes(*message));
    let mut signature = [[0u8; ELEMENT_BYTES]; CHAINS];
    for ((chain_index, value), digit) in (0u32..).zip(signature.iter_mut()).zip(digits) {
        let start = secret_start(secret_seed, public_seed, tree, key_pair, chain_index)?;
        *value = chain(public_seed, tree, key_pair, chain_index, &start, 0, digit)?;
    }

    Ok(signature)
}

/// FIPS 205 Algorithm 8: finishes each revealed chain and compresses the ends. The
/// result equals the key's public key only for a valid signature of `message`.
pub(crate) fn public_key_from_signature(
    signature: &WotsSignature,
    message: &[u8; ELEMENT_BYTES],
    public_seed: &PublicSeed,
    tree: TreePosition,
    key_pair: u32,
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    let digits = message_digits(&MessageDigest::from_bytes(*message));
    let mut ends = [[0u8; ELEMENT_BYTES]; CHAINS];
    for (((chain_index, end), value), digit) in
        (0u32..).zip(ends.iter_mut()).zip(signature).zip(digits)
    {
        *end = chain(
            public_seed,
            tree,
            key_pair,
            chain_index,
            value,
            digit,
            BASE16_MAX - digit,
        )?;
    }

    compress_ends(public_seed, tree, key_pair, &ends)
}

/// The secret start of one chain: PRF over the secret seed and a WOTS_PRF address.
fn secret_start(
    secret_seed: &SecretSeed,
    public_seed: &PublicSeed,
    tree: TreePosition,
    key_pair: u32,
    chain_index: u32,
) -> Result<Zeroizing<[u8; ELEMENT_BYTES]>, AddressError> {
    let address = compress(&wots_secret_address(tree, key_pair, chain_index)?);
    Ok(Zeroizing::new(fips205::prf(
        public_seed.as_bytes(),
        &secret_seed.0,
        &address,
    )))
}

/// FIPS 205 Algorithm 5: hashes `value`, which sits at position `start` of its
/// chain, `steps` times. Returns InvalidStep if the chain would pass position 15.
fn chain(
    public_seed: &PublicSeed,
    tree: TreePosition,
    key_pair: u32,
    chain_index: u32,
    value: &[u8; ELEMENT_BYTES],
    start: u8,
    steps: u8,
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    let mut current = Zeroizing::new(*value);
    for step in u32::from(start)..u32::from(start) + u32::from(steps) {
        let address = compress(&wots_hash_address(tree, key_pair, chain_index, step)?);
        *current = fips205::f(public_seed.as_bytes(), &address, &current);
    }

    Ok(*current)
}

/// Compresses the 67 chain ends with T_len under the key's WOTS_PK address.
fn compress_ends(
    public_seed: &PublicSeed,
    tree: TreePosition,
    key_pair: u32,
    ends: &[[u8; ELEMENT_BYTES]; CHAINS],
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    let address = compress(&wots_public_key_address(tree, key_pair)?);
    Ok(fips205::t(public_seed.as_bytes(), &address, ends))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POSITION: TreePosition = TreePosition {
        layer: 5,
        tree: 0x0abc,
    };

    // Fixed public test seeds, never for real signing.
    fn test_seeds() -> (SecretSeed, PublicSeed) {
        (
            SecretSeed::from_bytes([0x42; 32]),
            PublicSeed::from_bytes([0xa5; 32]),
        )
    }

    #[test]
    fn a_chain_split_in_two_reaches_the_same_value() {
        let (_, public_seed) = test_seeds();
        let value = [0x17; 32];

        for split in 0..=15 {
            let first = chain(&public_seed, POSITION, 3, 9, &value, 0, split).unwrap();
            assert_eq!(
                chain(&public_seed, POSITION, 3, 9, &first, split, 15 - split),
                chain(&public_seed, POSITION, 3, 9, &value, 0, 15),
                "split={split}"
            );
        }
        assert_eq!(
            chain(&public_seed, POSITION, 3, 9, &value, 15, 0),
            Ok(value)
        );
    }

    #[test]
    fn a_chain_past_position_fifteen_is_rejected() {
        let (_, public_seed) = test_seeds();

        assert_eq!(
            chain(&public_seed, POSITION, 3, 9, &[0; 32], 1, 15),
            Err(AddressError::InvalidStep)
        );
        assert_eq!(
            chain(&public_seed, POSITION, 3, 9, &[0; 32], 15, 1),
            Err(AddressError::InvalidStep)
        );
    }

    #[test]
    fn the_public_key_from_a_signature_is_the_generated_public_key() {
        let (secret_seed, public_seed) = test_seeds();
        let expected = public_key(&secret_seed, &public_seed, POSITION, 3).unwrap();

        for message in [[0; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
            let signature = sign(&message, &secret_seed, &public_seed, POSITION, 3).unwrap();
            assert_eq!(
                public_key_from_signature(&signature, &message, &public_seed, POSITION, 3),
                Ok(expected)
            );
        }
    }

    #[test]
    fn a_signature_checked_against_another_message_or_key_gives_another_public_key() {
        let (secret_seed, public_seed) = test_seeds();
        let expected = public_key(&secret_seed, &public_seed, POSITION, 3).unwrap();
        let message = [0x5a; 32];
        let signature = sign(&message, &secret_seed, &public_seed, POSITION, 3).unwrap();
        let mut other_message = message;
        other_message[31] ^= 1;

        assert_ne!(
            public_key_from_signature(&signature, &other_message, &public_seed, POSITION, 3),
            Ok(expected)
        );
        assert_ne!(
            public_key_from_signature(&signature, &message, &public_seed, POSITION, 4),
            Ok(expected)
        );
    }

    #[test]
    fn signing_reveals_each_chain_at_its_digit() {
        let (secret_seed, public_seed) = test_seeds();
        // Every message digit is 0, so the checksum is 64 * 15 = 0x3c0.
        let signature = sign(&[0; 32], &secret_seed, &public_seed, POSITION, 3).unwrap();

        for (chain_index, digit) in [(0u32, 0), (63, 0), (64, 3), (65, 12), (66, 0)] {
            let start = secret_start(&secret_seed, &public_seed, POSITION, 3, chain_index).unwrap();
            assert_eq!(
                Ok(signature[chain_index as usize]),
                chain(&public_seed, POSITION, 3, chain_index, &start, 0, digit),
                "chain={chain_index}"
            );
        }
    }

    #[test]
    fn keys_outside_the_xmss_tree_are_rejected() {
        let (secret_seed, public_seed) = test_seeds();

        assert_eq!(
            public_key(&secret_seed, &public_seed, POSITION, 16),
            Err(AddressError::InvalidKeyPair)
        );
    }
}
