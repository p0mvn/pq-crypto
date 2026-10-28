//! FORS shapes: k trees of height a with n-byte hash values, chosen by the const
//! parameters `K`, `A`, and `N` of the public types.

/// Rejects tree shapes the index and address encodings cannot hold: at least one
/// tree, heights 1 to 16 so each index fits in 16 bits, and at most 2^32 leaves so
/// every leaf index fits its 32-bit address field. Called in constant contexts, so
/// an unsupported shape fails to compile where it is first used.
pub(crate) const fn check_trees(trees: usize, tree_height: usize) {
    assert!(trees > 0, "a FORS key needs at least one tree");
    assert!(
        tree_height > 0 && tree_height <= 16,
        "FORS tree height a must be 1 to 16"
    );
    assert!(
        trees as u64 <= (1u64 << 32) >> tree_height,
        "a FORS key can hold at most 2^32 leaves"
    );
}

/// Rejects unsupported shapes as [`check_trees`] does, and hash lengths other than
/// the two whose hash functions this crate checks against NIST data: n = 16
/// (SHA-256 only) and n = 32 (SHA-256 and SHA-512).
pub(crate) const fn check_shape(trees: usize, tree_height: usize, n: usize) {
    check_trees(trees, tree_height);
    assert!(
        n == 16 || n == 32,
        "FORS hash length n must be 16 or 32 bytes"
    );
}
