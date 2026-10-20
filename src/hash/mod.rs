//! Internal hash operations used by WOTS+.
//! The current profile selects SHA-256; concrete hashing stays in this module.

mod sha2_256;

pub(crate) use sha2_256::{f, prf};
