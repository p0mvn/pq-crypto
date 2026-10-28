//! Hex decoding for fixed test vectors; compiled only for unit tests.

/// Decodes hex into bytes, ignoring spaces used to group fields.
pub(crate) fn hex_bytes(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|byte| *byte != b' ').collect();
    assert_eq!(digits.len() % 2, 0, "expected whole bytes of hex");
    digits
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Decodes hex into exactly N bytes, ignoring spaces used to group fields.
pub(crate) fn hex<const N: usize>(text: &str) -> [u8; N] {
    let bytes = hex_bytes(text);
    assert_eq!(bytes.len(), N, "expected {N} bytes of hex");
    std::array::from_fn(|i| bytes[i])
}
