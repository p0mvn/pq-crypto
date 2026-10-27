use std::{fmt::Write, path::Path};
use pq_crypto::{MessageDigest, PublicSeed, SecretSeed, wots::SigningKey};

fn main() {
    let directory = std::env::args().nth(1).expect("output directory");
    std::fs::create_dir_all(&directory).unwrap();
    let cases = [
        ("zero", [0; 32]),
        ("maximum", [255; 32]),
        ("patterned", std::array::from_fn(|i| i as u8)),
        ("mixed", [0xa7; 32]),
        ("alternating", [0x0f; 32]),
    ];
    for (name, digest) in cases {
        // Recreated public test seeds only, never a real signing key.
        let key = SigningKey::from_seeds(
            SecretSeed::from_bytes(std::array::from_fn(|i| i as u8)),
            PublicSeed::from_bytes(std::array::from_fn(|i| (31 - i) as u8)),
        )
        .unwrap();
        let signature = key.sign_digest(&MessageDigest::from_bytes(digest));
        let mut encoded = String::new();
        for chunk in signature.to_bytes().chunks_exact(32) {
            for byte in chunk {
                write!(encoded, "{byte:02x}").unwrap();
            }
            encoded.push('\n');
        }
        std::fs::write(
            Path::new(&directory).join(format!("signature_{name}.hex")),
            encoded,
        )
        .unwrap();
    }
}
