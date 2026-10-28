use pq_crypto::slh_dsa::{Context, Signature, SigningKey, VerifyingKey};

fn main() {
    let key = SigningKey::generate(&mut getrandom::SysRng)
        .expect("the system randomness source must be available");
    let public_bytes = key.verifying_key().to_bytes();
    // A fixed context string keeps signatures for this purpose apart from others.
    let context = Context::new(b"pq-crypto example").expect("the context is under 256 bytes");
    let signature_bytes = key
        .sign(b"0xtest", context, &mut getrandom::SysRng)
        .expect("the system randomness source must be available")
        .to_bytes();

    // A receiver parses the public data and verifies against an authenticated key.
    let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    public.verify(b"0xtest", context, &signature).unwrap();
    println!(
        "Signed and verified 0xtest with SLH-DSA-SHA2-256f after serializing the public key and signature."
    );
}
