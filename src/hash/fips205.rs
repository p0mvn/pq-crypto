//! SHA2 instantiation of the FIPS 205 tweakable hash functions for n = 16, 24, or 32.
//!
//! PRF and F always use SHA-256. H and T_l use SHA-256 for n = 16 (section 11.2.1,
//! security category 1) and SHA-512 for n = 24 and n = 32 (section 11.2.2,
//! categories 3 and 5). Every input starts with the public seed, zero-padded to one
//! full block of the hash in use, followed by the 22-byte compressed address; each
//! output is truncated to n bytes. PRF and F share one formula, as do H and T_l;
//! only the address type separates them.

use sha2::{Digest, Sha256, Sha512};

/// FIPS 205 sections 11.2.1 and 11.2.2:
/// Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || SK.seed)).
/// The complete hash input is 86 + n bytes; the secret seed comes after the address.
/// The output is secret: callers must keep it in cleared storage until it is revealed.
pub(crate) fn prf<const N: usize>(
    public_seed: &[u8; N],
    secret_seed: &[u8; N],
    address: &[u8; 22],
) -> [u8; N] {
    let mut hasher = sha256_after_seed_block(public_seed, address);
    hasher.update(secret_seed);

    first_bytes(&hasher.finalize())
}

/// FIPS 205 sections 11.2.1 and 11.2.2:
/// Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M_1)).
/// The complete hash input is 86 + n bytes.
pub(crate) fn f<const N: usize>(
    public_seed: &[u8; N],
    address: &[u8; 22],
    input: &[u8; N],
) -> [u8; N] {
    let mut hasher = sha256_after_seed_block(public_seed, address);
    hasher.update(input);

    first_bytes(&hasher.finalize())
}

/// FIPS 205 H, where M_2 is the left value followed by the right value. For n = 16:
/// Trunc_16(SHA-256(PK.seed || toByte(0, 48) || ADRSc || M_2)). For n = 24 and
/// n = 32: Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRSc || M_2)).
pub(crate) fn h<const N: usize>(
    public_seed: &[u8; N],
    address: &[u8; 22],
    left: &[u8; N],
    right: &[u8; N],
) -> [u8; N] {
    t(public_seed, address, &[*left, *right])
}

/// FIPS 205 T_l over the values concatenated in order, with the same hash and
/// padding as H; with two values it equals H.
pub(crate) fn t<const N: usize>(
    public_seed: &[u8; N],
    address: &[u8; 22],
    values: &[[u8; N]],
) -> [u8; N] {
    if N == 16 {
        let mut hasher = sha256_after_seed_block(public_seed, address);
        values.iter().for_each(|value| hasher.update(value));
        first_bytes(&hasher.finalize())
    } else {
        let mut hasher = sha512_after_seed_block(public_seed, address);
        values.iter().for_each(|value| hasher.update(value));
        first_bytes(&hasher.finalize())
    }
}

/// Starts SHA-256 with the public seed padded to its 64-byte block, then the address.
fn sha256_after_seed_block<const N: usize>(public_seed: &[u8; N], address: &[u8; 22]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(public_seed);
    hasher.update(&[0u8; 64][N..]);
    hasher.update(address);
    hasher
}

/// Starts SHA-512 with the public seed padded to its 128-byte block, then the address.
fn sha512_after_seed_block<const N: usize>(public_seed: &[u8; N], address: &[u8; 22]) -> Sha512 {
    let mut hasher = Sha512::new();
    hasher.update(public_seed);
    hasher.update(&[0u8; 128][N..]);
    hasher.update(address);
    hasher
}

fn first_bytes<const N: usize>(digest: &[u8]) -> [u8; N] {
    core::array::from_fn(|i| digest[i])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::hex;

    // Locally generated vectors for FIPS 205 sections 11.2.1 (n = 16) and 11.2.2
    // (n = 24 and n = 32), not vectors published by NIST. Expected outputs were calculated with
    // Python hashlib and cross-checked with openssl dgst. Inputs are runs of
    // consecutive bytes: public seed from 00, secret seed or first value from 20,
    // second value from 60, each n bytes long, and address 40..55.
    const PUBLIC_SEED: [u8; 32] = consecutive_bytes(0x00);
    const FIRST_VALUE: [u8; 32] = consecutive_bytes(0x20);
    const SECOND_VALUE: [u8; 32] = consecutive_bytes(0x60);
    const ADDRESS: [u8; 22] = consecutive_bytes(0x40);
    const SHORT_PUBLIC_SEED: [u8; 16] = consecutive_bytes(0x00);
    const SHORT_FIRST_VALUE: [u8; 16] = consecutive_bytes(0x20);
    const SHORT_SECOND_VALUE: [u8; 16] = consecutive_bytes(0x60);

    const fn consecutive_bytes<const N: usize>(start: u8) -> [u8; N] {
        let mut bytes = [0u8; N];
        let mut i = 0;
        while i < N {
            bytes[i] = start + i as u8;
            i += 1;
        }
        bytes
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
        let roots: [[u8; 32]; 35] = core::array::from_fn(|i| [i as u8; 32]);

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

    #[test]
    fn prf_and_f_for_n_16_keep_the_first_half_of_sha256_over_a_48_byte_pad() {
        for output in [
            prf(&[0; 16], &[0; 16], &[0; 22]),
            f(&[0; 16], &[0; 22], &[0; 16]),
        ] {
            assert_eq!(output, hex("c419a92c7dce5225606f604f79d0d070"));
        }
        for output in [
            prf(&SHORT_PUBLIC_SEED, &SHORT_FIRST_VALUE, &ADDRESS),
            f(&SHORT_PUBLIC_SEED, &ADDRESS, &SHORT_FIRST_VALUE),
        ] {
            assert_eq!(output, hex("286fb5c922d35c64c43cae1915f591d2"));
        }
    }

    #[test]
    fn h_for_n_16_uses_sha256_instead_of_sha512() {
        // All-zero input is the same 118 bytes as the all-zero n = 32 PRF input.
        assert_eq!(
            h(&[0; 16], &[0; 22], &[0; 16], &[0; 16]),
            hex("017ab4b70ea129c29e932d44baddc185"),
        );
        assert_eq!(
            h(
                &SHORT_PUBLIC_SEED,
                &ADDRESS,
                &SHORT_FIRST_VALUE,
                &SHORT_SECOND_VALUE
            ),
            hex("7bca3eba3963679322c65b75b136f547"),
        );
        assert_eq!(
            h(
                &SHORT_PUBLIC_SEED,
                &ADDRESS,
                &SHORT_SECOND_VALUE,
                &SHORT_FIRST_VALUE
            ),
            hex("1e20fd2c8c8af1407711e848a2c77873"),
        );
    }

    #[test]
    fn t_for_n_16_matches_an_independently_calculated_vector() {
        // Fourteen values, as SLH-DSA-SHA2-128s's FORS combines its tree roots.
        let roots: [[u8; 16]; 14] = core::array::from_fn(|i| [i as u8; 16]);

        assert_eq!(
            t(&SHORT_PUBLIC_SEED, &ADDRESS, &roots),
            hex("8ec09755096c44d8e3a890ea4cb6794d"),
        );
    }

    #[test]
    fn prf_and_f_for_n_24_keep_24_bytes_of_sha256_over_a_40_byte_pad() {
        let public_seed: [u8; 24] = consecutive_bytes(0x00);
        let first: [u8; 24] = consecutive_bytes(0x20);

        for output in [
            prf(&[0; 24], &[0; 24], &[0; 22]),
            f(&[0; 24], &[0; 22], &[0; 24]),
        ] {
            assert_eq!(
                output,
                hex("f23391587f1c9fc48eabd1e95f4caf16f585ef09941b7bc2")
            );
        }
        for output in [
            prf(&public_seed, &first, &ADDRESS),
            f(&public_seed, &ADDRESS, &first),
        ] {
            assert_eq!(
                output,
                hex("761a2fda9eb72677622dfdd7da8573a0877830887527913e")
            );
        }
    }

    #[test]
    fn h_and_t_for_n_24_keep_24_bytes_of_sha512_over_a_104_byte_pad() {
        let public_seed: [u8; 24] = consecutive_bytes(0x00);
        let first: [u8; 24] = consecutive_bytes(0x20);
        let second: [u8; 24] = consecutive_bytes(0x60);
        // Seventeen values, as SLH-DSA-SHA2-192s's FORS combines its tree roots.
        let roots: [[u8; 24]; 17] = std::array::from_fn(|i| [i as u8; 24]);

        assert_eq!(
            h(&[0; 24], &[0; 22], &[0; 24], &[0; 24]),
            hex("3b693bd217c3d1ca188c975a8da4b58c5c74e3556be4563c"),
        );
        assert_eq!(
            h(&public_seed, &ADDRESS, &first, &second),
            hex("a4cbba18e47128b11215d2850d942da3f9cb193869315840"),
        );
        assert_eq!(
            h(&public_seed, &ADDRESS, &second, &first),
            hex("3f8beb6e1192d853df3da34e83ed106a2be1d31f105e6a13"),
        );
        assert_eq!(
            t(&public_seed, &ADDRESS, &roots),
            hex("249307f60d07709903937c375869eecc885b783f702c91fb"),
        );
    }
}
