use pq_crypto::fors::{INDEX_DIGEST_BYTES, IndexDigest, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

fn main() {
    let key = SigningKey::generate(&mut getrandom::SysRng)
        .expect("the system randomness source must be available");
    let public_bytes = key.verifying_key().to_bytes();
    // FORS signs 40 bytes; here they are the first 40 bytes of SHA-512.
    let digest = IndexDigest::try_from(&Sha512::digest(b"0xtest")[..INDEX_DIGEST_BYTES])
        .expect("SHA-512 output is longer than a FORS digest");
    let signature_bytes = key.sign_digest(&digest).to_bytes();

    // A receiver parses the public data and verifies against an authenticated key.
    let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    public.verify_digest(&digest, &signature).unwrap();
    println!(
        "Signed and verified 0xtest with FORS after serializing the public key and signature."
    );
}
