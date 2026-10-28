//! SLH-DSA-SHA2-256f parameters (FIPS 205 section 11, table 2) and the sizes they give.

use crate::fors::{IndexDigest, Signature as FullForsSignature};
use crate::params::ELEMENT_BYTES;
use crate::wots::CHAINS;

/// The randomizer, the FORS signature, then for each of the 17 layers 67 WOTS+
/// values and 4 authentication-path nodes, each 32 bytes.
pub const SIGNATURE_BYTES: usize = 49_856;
/// The public seed followed by the hypertree root.
pub const VERIFYING_KEY_BYTES: usize = 64;
/// The longest context string FIPS 205 accepts.
pub const MAX_CONTEXT_BYTES: usize = 255;

/// FORS: k = 35 trees of height a = 9.
pub(crate) const FORS_TREES: usize = 35;
pub(crate) const FORS_HEIGHT: usize = 9;
/// Hypertree: d = 17 layers of XMSS trees of height h' = 4, total height h = 68.
pub(crate) const LAYERS: usize = 17;
pub(crate) const XMSS_HEIGHT: usize = 4;
pub(crate) const XMSS_LEAVES: u32 = 1 << XMSS_HEIGHT;
/// The H_msg output, m = 49 bytes: the 40-byte FORS digest, 8 bytes that select the
/// bottom-layer tree, and 1 byte whose low 4 bits select the leaf in it.
pub(crate) const MESSAGE_DIGEST_BYTES: usize = 49;
pub(crate) const FORS_DIGEST_BYTES: usize = 40;
pub(crate) const TREE_INDEX_BYTES: usize = 8;

pub(crate) type ForsDigest = IndexDigest<FORS_TREES, FORS_HEIGHT>;
pub(crate) type ForsSignature = FullForsSignature<FORS_TREES, FORS_HEIGHT, ELEMENT_BYTES>;
pub(crate) const FORS_SIGNATURE_BYTES: usize = ForsSignature::BYTES;

const _: () = assert!(LAYERS * XMSS_HEIGHT == 68);
const _: () = assert!(FORS_DIGEST_BYTES == ForsDigest::BYTES);
// The tree index takes all h - h' = 64 bits of its bytes, and the leaf index fits one.
const _: () = assert!(TREE_INDEX_BYTES * 8 == (LAYERS - 1) * XMSS_HEIGHT);
const _: () = assert!(XMSS_HEIGHT <= 8);
const _: () = assert!(MESSAGE_DIGEST_BYTES == FORS_DIGEST_BYTES + TREE_INDEX_BYTES + 1);
const _: () = assert!(
    SIGNATURE_BYTES
        == ELEMENT_BYTES + FORS_SIGNATURE_BYTES + LAYERS * (CHAINS + XMSS_HEIGHT) * ELEMENT_BYTES
);
const _: () = assert!(VERIFYING_KEY_BYTES == 2 * ELEMENT_BYTES);
