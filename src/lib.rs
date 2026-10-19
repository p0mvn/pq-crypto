//! API scaffold for standalone RFC 8391 WOTS+.
//!
//! Digest and public-seed value helpers are implemented; other functions panic.
//! This crate cannot generate keys, sign, parse, or verify yet.

#![forbid(unsafe_code)]

pub mod sha2_256;
