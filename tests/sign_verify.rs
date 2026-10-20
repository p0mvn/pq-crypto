use sha2::{Digest, Sha256};
use wots::{MessageDigest, PublicSeed, SecretSeed, SigningKey};

#[test]
fn sign_and_verify_test_bytes() {
    let message = b"0xtest";
    let digest = MessageDigest::from_bytes(Sha256::digest(message).into());

    // Fixed public test seeds, never for real signing.
    let signing_key = SigningKey::from_seeds(
        SecretSeed::from_bytes([0x42; 32]),
        PublicSeed::from_bytes([0xa5; 32]),
    )
    .unwrap();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign_digest(&digest);

    assert_eq!(verifying_key.verify_digest(&digest, &signature), Ok(()));
}
