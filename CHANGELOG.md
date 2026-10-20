# Changelog

## Unreleased

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
