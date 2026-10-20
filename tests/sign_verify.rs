use sha2::{Digest, Sha256};
use wots_plus::{
    MessageDigest, PublicSeed, SecretSeed, Signature, SigningKey, VerifyError, VerifyingKey,
};

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

#[test]
fn randomly_generated_key_survives_public_serialization_and_rejects_a_changed_message() {
    let key = SigningKey::generate(&mut getrandom::SysRng).unwrap();
    let public_bytes = key.verifying_key().to_bytes();
    let digest = MessageDigest::from_bytes(Sha256::digest(b"0xtest").into());
    let signature_bytes = key.sign_digest(&digest).to_bytes();

    let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    assert_eq!(public.verify_digest(&digest, &signature), Ok(()));
    let changed = MessageDigest::from_bytes(Sha256::digest(b"0xtest!").into());
    assert_eq!(
        public.verify_digest(&changed, &signature),
        Err(VerifyError::InvalidSignature)
    );
}
