use sha2::{Digest, Sha256};
use wots_plus::{
    MessageDigest,
    wots::{Signature, SigningKey, VerifyingKey},
};

fn main() {
    let key = SigningKey::generate(&mut getrandom::SysRng)
        .expect("the system randomness source must be available");
    let public_bytes = key.verifying_key().to_bytes();
    let digest = MessageDigest::from_bytes(Sha256::digest(b"0xtest").into());
    let signature_bytes = key.sign_digest(&digest).to_bytes();

    // A receiver parses the public data and verifies against an authenticated key.
    let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    public.verify_digest(&digest, &signature).unwrap();
    println!("Signed and verified 0xtest after serializing the public key and signature.");
}
