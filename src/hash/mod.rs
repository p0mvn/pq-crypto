//! Internal hash operations shared across the crate; concrete hashing stays in this module.
//! WOTS+ uses the RFC 8391 SHA-256 functions re-exported here. FORS uses the FIPS 205
//! SHA2 functions in [`fips205`], whose names would otherwise collide with them.

pub(crate) mod fips205;
mod sha2_256;

pub(crate) use sha2_256::{f, prf, prf_keygen};
