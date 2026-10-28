//! Context strings, the message prefix of the external interface, and the parts of
//! the message digest.

use crate::fors::KeyPosition;
use crate::slh_dsa::params::{
    FORS_DIGEST_BYTES, ForsDigest, MAX_CONTEXT_BYTES, MESSAGE_DIGEST_BYTES, TREE_INDEX_BYTES,
    XMSS_LEAVES,
};

/// A FIPS 205 context string of at most 255 bytes. It is hashed with the message, so
/// a signature made under one context fails under every other, including the empty
/// one. Applications can fix one context per purpose so that a signature made for
/// one purpose is not accepted for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context<'a>(&'a [u8]);

impl<'a> Context<'a> {
    /// The empty context, used when an application sets none.
    pub const EMPTY: Self = Self(&[]);

    /// Accepts at most [`MAX_CONTEXT_BYTES`] bytes, the limit FIPS 205 sets.
    pub fn new(bytes: &'a [u8]) -> Result<Self, ContextError> {
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(ContextError::TooLong);
        }

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// FIPS 205 Algorithms 22 and 24 hash toByte(0, 1) || toByte(|ctx|, 1) || ctx
    /// before the message; this returns the first two bytes. The leading 0 marks a
    /// pure signature, where HashSLH-DSA would write 1.
    pub(crate) fn prefix(&self) -> [u8; 2] {
        let length = u8::try_from(self.0.len()).expect("Context::new limits the length");
        [0, length]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextError {
    TooLong,
}

/// The parts of a 49-byte H_msg digest (FIPS 205 Algorithm 19, lines 7 to 12): the
/// digest the FORS key signs, and which FORS key signs it, the one at `leaf` of
/// bottom-layer tree `tree`.
pub(crate) struct DigestParts {
    pub(crate) fors_digest: ForsDigest,
    pub(crate) tree: u64,
    pub(crate) leaf: u32,
}

impl DigestParts {
    /// Bytes 0 to 39 are the FORS digest. Bytes 40 to 47 are the tree index, which
    /// keeps all h - h' = 64 bits. The low h' = 4 bits of byte 48 are the leaf.
    pub(crate) fn split(digest: &[u8; MESSAGE_DIGEST_BYTES]) -> Self {
        let (fors_bytes, rest) = digest
            .split_first_chunk::<FORS_DIGEST_BYTES>()
            .expect("the digest starts with the FORS digest");
        let (tree_bytes, [leaf_byte]) = rest
            .split_first_chunk::<TREE_INDEX_BYTES>()
            .expect("the tree index follows the FORS digest")
        else {
            unreachable!("one leaf byte follows the tree index")
        };

        Self {
            fors_digest: ForsDigest::from_bytes(*fors_bytes),
            tree: u64::from_be_bytes(*tree_bytes),
            leaf: u32::from(*leaf_byte) % XMSS_LEAVES,
        }
    }

    /// The FORS key's position in the bottom layer: its tree, and its leaf as the
    /// key pair.
    pub(crate) fn fors_position(&self) -> KeyPosition {
        KeyPosition {
            tree: self.tree,
            key_pair: self.leaf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_up_to_255_bytes_are_accepted_and_longer_ones_rejected() {
        let bytes = [0x63; 256];

        assert_eq!(
            Context::new(&bytes[..255]).unwrap().as_bytes(),
            &bytes[..255]
        );
        assert_eq!(Context::new(&bytes), Err(ContextError::TooLong));
        assert_eq!(Context::new(&[]), Ok(Context::EMPTY));
    }

    #[test]
    fn the_prefix_is_a_zero_byte_and_the_context_length() {
        assert_eq!(Context::EMPTY.prefix(), [0, 0]);
        assert_eq!(Context::new(b"ctx").unwrap().prefix(), [0, 3]);
        assert_eq!(Context::new(&[0; 255]).unwrap().prefix(), [0, 255]);
    }

    #[test]
    fn the_digest_splits_into_the_fors_digest_tree_and_leaf() {
        let digest: [u8; 49] = std::array::from_fn(|i| match i {
            0..40 => 0xa5,
            40..48 => i as u8,
            _ => 0xf7,
        });
        let parts = DigestParts::split(&digest);

        assert_eq!(parts.fors_digest, ForsDigest::from_bytes([0xa5; 40]));
        assert_eq!(parts.tree, 0x2829_2a2b_2c2d_2e2f);
        // Only the low four bits of the last byte select the leaf.
        assert_eq!(parts.leaf, 7);
        assert_eq!(
            parts.fors_position(),
            KeyPosition {
                tree: 0x2829_2a2b_2c2d_2e2f,
                key_pair: 7
            }
        );
    }
}
