//! SHA2 instantiation of the FIPS 205 tweakable hash functions for n = 32.
//!
//! FIPS 205 section 11.2.2 (security categories 3 and 5) uses SHA-256 for PRF and F
//! and SHA-512 for H and T_l. Every input starts with the public seed, zero-padded
//! to one full block of the hash in use, followed by the 22-byte compressed address.
//! PRF and F share one formula, as do H and T_l; only the address type separates them.

use sha2::{Digest, Sha256, Sha512};

/// FIPS 205 section 11.2.2: SHA-256(PK.seed || toByte(0, 32) || ADRSc || SK.seed).
/// The complete hash input is 118 bytes; the secret seed comes after the address.
/// The output is secret: callers must keep it in cleared storage until it is revealed.
pub(crate) fn prf(public_seed: &[u8; 32], secret_seed: &[u8; 32], address: &[u8; 22]) -> [u8; 32] {
    let mut hasher = sha256_after_seed_block(public_seed, address);
    hasher.update(secret_seed);

    hasher.finalize().into()
}

/// FIPS 205 section 11.2.2: SHA-256(PK.seed || toByte(0, 32) || ADRSc || M_1).
/// The complete hash input is 118 bytes.
pub(crate) fn f(public_seed: &[u8; 32], address: &[u8; 22], input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha256_after_seed_block(public_seed, address);
    hasher.update(input);

    hasher.finalize().into()
}

/// FIPS 205 section 11.2.2: Trunc_32(SHA-512(PK.seed || toByte(0, 96) || ADRSc || M_2)),
/// where M_2 is the left value followed by the right value. The complete hash input
/// is 214 bytes; the result is the first 32 bytes of the SHA-512 output.
pub(crate) fn h(
    public_seed: &[u8; 32],
    address: &[u8; 22],
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = sha512_after_seed_block(public_seed, address);
    hasher.update(left);
    hasher.update(right);

    first_32_bytes(hasher.finalize().into())
}

/// FIPS 205 section 11.2.2: Trunc_32(SHA-512(PK.seed || toByte(0, 96) || ADRSc || M_l)),
/// where M_l is the values concatenated in order. With two values this equals H.
pub(crate) fn t(public_seed: &[u8; 32], address: &[u8; 22], values: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = sha512_after_seed_block(public_seed, address);
    for value in values {
        hasher.update(value);
    }

    first_32_bytes(hasher.finalize().into())
}

/// Starts SHA-256 with the public seed padded to its 64-byte block, then the address.
fn sha256_after_seed_block(public_seed: &[u8; 32], address: &[u8; 22]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(public_seed);
    hasher.update([0u8; 32]);
    hasher.update(address);
    hasher
}

/// Starts SHA-512 with the public seed padded to its 128-byte block, then the address.
fn sha512_after_seed_block(public_seed: &[u8; 32], address: &[u8; 22]) -> Sha512 {
    let mut hasher = Sha512::new();
    hasher.update(public_seed);
    hasher.update([0u8; 96]);
    hasher.update(address);
    hasher
}

fn first_32_bytes(digest: [u8; 64]) -> [u8; 32] {
    std::array::from_fn(|i| digest[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Locally generated vectors for FIPS 205 section 11.2.2 with n = 32, not vectors
    // published by NIST. Expected outputs were calculated with Python hashlib and
    // cross-checked with openssl dgst. Inputs are runs of consecutive bytes:
    // public seed 00..1f, secret seed or first value 20..3f, second value 60..7f,
    // and address 40..55.
    const PUBLIC_SEED: [u8; 32] = consecutive_bytes(0x00);
    const FIRST_VALUE: [u8; 32] = consecutive_bytes(0x20);
    const SECOND_VALUE: [u8; 32] = consecutive_bytes(0x60);
    const ADDRESS: [u8; 22] = consecutive_bytes(0x40);

    const fn consecutive_bytes<const N: usize>(start: u8) -> [u8; N] {
        let mut bytes = [0u8; N];
        let mut i = 0;
        while i < N {
            bytes[i] = start + i as u8;
            i += 1;
        }
        bytes
    }

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[test]
    fn prf_matches_independently_calculated_vectors() {
        assert_eq!(
            prf(&[0; 32], &[0; 32], &[0; 22]),
            hex("017ab4b70ea129c29e932d44baddc185ad136bf719c4ada63a10b5bf796af91e"),
        );
        assert_eq!(
            prf(&PUBLIC_SEED, &FIRST_VALUE, &ADDRESS),
            hex("e77f1e9c23751562f62b9f1129862af336bb16309aae74ee358a1b1d6c21ae26"),
        );
    }

    #[test]
    fn f_matches_independently_calculated_vectors() {
        assert_eq!(
            f(&[0; 32], &[0; 22], &[0; 32]),
            hex("017ab4b70ea129c29e932d44baddc185ad136bf719c4ada63a10b5bf796af91e"),
        );
        assert_eq!(
            f(&PUBLIC_SEED, &ADDRESS, &FIRST_VALUE),
            hex("e77f1e9c23751562f62b9f1129862af336bb16309aae74ee358a1b1d6c21ae26"),
        );
    }

    #[test]
    fn prf_and_f_share_a_formula_so_only_the_address_separates_them() {
        let mut other_address = ADDRESS;
        other_address[9] ^= 1;

        assert_eq!(
            prf(&PUBLIC_SEED, &FIRST_VALUE, &ADDRESS),
            f(&PUBLIC_SEED, &ADDRESS, &FIRST_VALUE),
        );
        assert_ne!(
            prf(&PUBLIC_SEED, &FIRST_VALUE, &ADDRESS),
            f(&PUBLIC_SEED, &other_address, &FIRST_VALUE),
        );
    }

    #[test]
    fn h_matches_independently_calculated_vectors_in_input_order() {
        assert_eq!(
            h(&[0; 32], &[0; 22], &[0; 32], &[0; 32]),
            hex("4599567897e71bc3e4052a75fadfc14aceee8fbf5d50d42e43408b78a465649b"),
        );
        assert_eq!(
            h(&PUBLIC_SEED, &ADDRESS, &FIRST_VALUE, &SECOND_VALUE),
            hex("2febf50f1bbd6851066ac8dd85bb8b58a4609d3d02ce9d620274e946b53005e3"),
        );
        // Swapping the children gives an unrelated parent.
        assert_eq!(
            h(&PUBLIC_SEED, &ADDRESS, &SECOND_VALUE, &FIRST_VALUE),
            hex("d3de09bead65ea2b92f3b5fef423cc92e96fad3104d4ac0aa2db96ebbdcc93ba"),
        );
    }

    #[test]
    fn h_keeps_the_first_half_of_the_sha512_output() {
        let full: [u8; 64] = hex(concat!(
            "2febf50f1bbd6851066ac8dd85bb8b58a4609d3d02ce9d620274e946b53005e3",
            "4954c40c153fd670cf183b5b1ad4454e1444cf13165376e9cecc35e7798c31f1",
        ));

        assert_eq!(
            h(&PUBLIC_SEED, &ADDRESS, &FIRST_VALUE, &SECOND_VALUE),
            full[..32]
        );
    }

    #[test]
    fn t_matches_independently_calculated_vectors() {
        // Thirty-five values, as FORS combines its tree roots; value i repeats byte i.
        let roots: [[u8; 32]; 35] = std::array::from_fn(|i| [i as u8; 32]);

        assert_eq!(
            t(&PUBLIC_SEED, &ADDRESS, &roots),
            hex("c0c6efc522a0125b84d5933e54e20e7c086479d665d3181c4e2f1334391f2f82"),
        );
    }

    #[test]
    fn t_over_two_values_equals_h() {
        assert_eq!(
            t(&PUBLIC_SEED, &ADDRESS, &[FIRST_VALUE, SECOND_VALUE]),
            h(&PUBLIC_SEED, &ADDRESS, &FIRST_VALUE, &SECOND_VALUE),
        );
    }
}
