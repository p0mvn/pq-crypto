# Changelog

## [Unreleased]

### Added

- The crate builds without the standard library (`no_std`), so it runs on
  microcontrollers such as the Keystone hardware wallet's Cortex-M4F. CI
  builds it for `thumbv7em-none-eabihf`.

## [0.1.0-rc2] - 2026-10-27

### Changed

- The crate is renamed from `wots-plus` to `pq-crypto`; Rust code imports it as
  `pq_crypto`. Releases 0.1.0-rc0 and 0.1.0-rc1 were published as `wots-plus`.
- WOTS+ types and sizes moved into the `wots` module: import `SigningKey`,
  `VerifyingKey`, `Signature`, `VerifyError`, `SeedError`, `KeyGenerationError`,
  `SIGNATURE_BYTES`, and `VERIFYING_KEY_BYTES` from `pq_crypto::wots`.
  `PublicSeed`, `SecretSeed`, `MessageDigest`, `DecodeError`, and `DIGEST_BYTES`
  stay at the crate root. Keys, encodings, and signatures are unchanged.

## [0.1.0-rc1] - 2026-10-20

### Changed

- Secret chain starts now use the NIST SP 800-208 key generation PRF over the
  secret seed, the public seed, and the chain address, as the XMSS reference
  implementation does, instead of the informative RFC 8391 section 3.1.7
  derivation. Keys, public keys, and signatures differ from 0.1.0-rc0 for the
  same seeds.
- The equal-seeds check compares every byte without returning early.
- The C reference cross-check compiles the pinned reference unchanged, so it now
  covers key generation, and runs on pull requests.

## [0.1.0-rc0] - 2026-10-20

### Added

- Standalone WOTS+ signatures using the RFC 8391 `WOTSP-SHA2_256` profile:
  SHA-256, 32-byte digests, and base-16 hash chains.
- Key generation from caller-supplied cryptographic randomness, seed import,
  and full public-key generation.
- Signing that consumes the signing key, with repeatable signature verification.
- Raw serialization and exact-length parsing for 2,144-byte signatures and
  2,176-byte public keys.
- Zeroizing storage for managed secrets and hash state.
- API usage examples, construction and proof notes, fixed test vectors, and
  cross-checks against a pinned XMSS C reference implementation.
- Dual licensing under MIT or Apache-2.0, at the user's option.
