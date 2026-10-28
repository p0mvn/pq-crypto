use pq_crypto::{
    PublicSeed, SecretSeed,
    slh_dsa::{Context, PrfKey, SIGNATURE_BYTES, Signature, SigningKey, VerifyError, VerifyingKey},
};

// Fixed public test seeds, never for real signing.
fn test_key() -> SigningKey {
    SigningKey::from_seeds(
        SecretSeed::from_bytes([0x42; 32]),
        PrfKey::from_bytes([0x24; 32]),
        PublicSeed::from_bytes([0xa5; 32]),
    )
    .unwrap()
}

fn context(bytes: &[u8]) -> Context<'_> {
    Context::new(bytes).unwrap()
}

#[test]
fn sign_and_verify_test_bytes() {
    let key = test_key();
    let signature = key.sign_deterministic(b"0xtest", Context::EMPTY);

    assert_eq!(
        key.verifying_key()
            .verify(b"0xtest", Context::EMPTY, &signature),
        Ok(())
    );
}

#[test]
fn randomly_generated_key_survives_public_serialization_and_rejects_a_changed_message() {
    let key = SigningKey::generate(&mut getrandom::SysRng).unwrap();
    let public_bytes = key.verifying_key().to_bytes();
    let signature_bytes = key
        .sign(b"0xtest", context(b"app"), &mut getrandom::SysRng)
        .unwrap()
        .to_bytes();

    let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    assert_eq!(
        public.verify(b"0xtest", context(b"app"), &signature),
        Ok(())
    );
    assert_eq!(
        public.verify(b"0xtest!", context(b"app"), &signature),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn a_signature_verifies_only_under_the_context_it_was_made_with() {
    let key = test_key();
    let public = key.verifying_key();
    let contexts = [
        Context::EMPTY,
        context(b"a"),
        context(b"b"),
        context(&[0; 255]),
    ];
    let signatures = contexts.map(|context| key.sign_deterministic(b"0xtest", context));

    for (signed, signature) in signatures.iter().enumerate() {
        for (checked, context) in contexts.iter().enumerate() {
            let expected = if signed == checked {
                Ok(())
            } else {
                Err(VerifyError::InvalidSignature)
            };
            assert_eq!(
                public.verify(b"0xtest", *context, signature),
                expected,
                "signed context={signed}, checked context={checked}",
            );
        }
    }
}

#[test]
fn one_key_signs_several_messages_and_each_signature_verifies_only_for_its_own() {
    let key = test_key();
    let public = key.verifying_key();
    let messages: [&[u8]; 3] = [b"", b"second", &[0x5a; 1000]];
    let signatures = messages.map(|message| key.sign_deterministic(message, Context::EMPTY));

    for (signed, signature) in signatures.iter().enumerate() {
        for (checked, message) in messages.iter().enumerate() {
            let expected = if signed == checked {
                Ok(())
            } else {
                Err(VerifyError::InvalidSignature)
            };
            assert_eq!(
                public.verify(message, Context::EMPTY, signature),
                expected,
                "signed message={signed}, checked message={checked}",
            );
        }
    }
}

#[test]
fn hedged_signatures_of_one_message_differ_and_both_verify() {
    let key = test_key();
    let public = key.verifying_key();
    let first = key
        .sign(b"0xtest", Context::EMPTY, &mut getrandom::SysRng)
        .unwrap();
    let second = key
        .sign(b"0xtest", Context::EMPTY, &mut getrandom::SysRng)
        .unwrap();

    assert_ne!(first, second);
    assert_eq!(public.verify(b"0xtest", Context::EMPTY, &first), Ok(()));
    assert_eq!(public.verify(b"0xtest", Context::EMPTY, &second), Ok(()));
}

#[test]
fn deterministic_signing_is_repeatable() {
    let key = test_key();

    assert_eq!(
        key.sign_deterministic(b"0xtest", context(b"app")),
        key.sign_deterministic(b"0xtest", context(b"app"))
    );
}

#[test]
fn verification_rejects_a_change_in_each_part_of_the_signature() {
    let key = test_key();
    let public = key.verifying_key();
    let bytes = key.sign_deterministic(b"0xtest", Context::EMPTY).to_bytes();

    // Checking every one of the 1,558 values would take 1,558 verifications, so this
    // changes the randomizer, the first and last FORS values, and in each of the 17
    // layers the first WOTS+ value and the last authentication-path node.
    let fors_end = 32 + 11_200;
    let layer_bytes = (67 + 4) * 32;
    let mut values = vec![0, 32, fors_end - 32];
    for layer in 0..17 {
        let start = fors_end + layer * layer_bytes;
        values.extend([start, start + layer_bytes - 32]);
    }
    assert_eq!(values.last(), Some(&(SIGNATURE_BYTES - 32)));

    for offset in values {
        let mut changed = bytes;
        changed[offset + 31] ^= 0x80;
        assert_eq!(
            public.verify(b"0xtest", Context::EMPTY, &Signature::from_bytes(&changed)),
            Err(VerifyError::InvalidSignature),
            "offset={offset}",
        );
    }
}

#[test]
fn verification_rejects_a_signature_from_another_key() {
    let other_key = SigningKey::from_seeds(
        SecretSeed::from_bytes([0x43; 32]),
        PrfKey::from_bytes([0x24; 32]),
        PublicSeed::from_bytes([0xa5; 32]),
    )
    .unwrap();

    assert_eq!(
        test_key().verifying_key().verify(
            b"0xtest",
            Context::EMPTY,
            &other_key.sign_deterministic(b"0xtest", Context::EMPTY)
        ),
        Err(VerifyError::InvalidSignature)
    );
}
