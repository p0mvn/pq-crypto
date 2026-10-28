use std::time::Instant;

use pq_crypto::fors::{IndexDigest, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

fn main() {
    // Each shape is K trees of height A with N-byte hash values.
    sign_and_verify::<35, 9, 32, 64, 11_200>("SLH-DSA-SHA2-256f's FORS");
    sign_and_verify::<22, 14, 32, 64, 10_560>("SLH-DSA-SHA2-256s's FORS");
    sign_and_verify::<16, 16, 32, 64, 8_704>("16 trees of height 16");
    sign_and_verify::<14, 12, 16, 32, 2_912>("SLH-DSA-SHA2-128s's FORS");
}

/// Signs and verifies 0xtest with a fresh key of one shape, after serializing the
/// PUBLIC-byte public key and SIGNATURE-byte signature, and prints the timings.
fn sign_and_verify<
    const K: usize,
    const A: usize,
    const N: usize,
    const PUBLIC: usize,
    const SIGNATURE: usize,
>(
    name: &str,
) {
    let start = Instant::now();
    let key = SigningKey::<K, A, N>::generate(&mut getrandom::SysRng)
        .expect("the system randomness source must be available");
    let public_bytes: [u8; PUBLIC] = key.verifying_key().to_bytes();
    let key_generation = start.elapsed();

    // FORS signs K * A bits; here they are the first bytes of SHA-512.
    let digest_bytes = &Sha512::digest(b"0xtest")[..IndexDigest::<K, A>::BYTES];
    let digest = IndexDigest::try_from(digest_bytes).expect("the length matches the shape");
    let start = Instant::now();
    let signature_bytes: [u8; SIGNATURE] = key.sign_digest(&digest).to_bytes();
    let signing = start.elapsed();

    // A receiver parses the public data and verifies against an authenticated key.
    let public = VerifyingKey::<K, A, N>::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    let start = Instant::now();
    public.verify_digest(&digest, &signature).unwrap();
    let verification = start.elapsed();

    println!(
        "{name} (k = {K}, a = {A}, n = {N}): {SIGNATURE}-byte signature, \
         key generation {key_generation:.1?}, signing {signing:.1?}, \
         verification {verification:.1?}"
    );
}
