//! Hex decoding for fixed test vectors; compiled only for unit tests.

/// Decodes hex into exactly N bytes, ignoring spaces used to group fields.
pub(crate) fn hex<const N: usize>(text: &str) -> [u8; N] {
    let digits: Vec<u8> = text.bytes().filter(|byte| *byte != b' ').collect();
    assert_eq!(digits.len(), N * 2, "expected {N} bytes of hex");
    core::array::from_fn(|i| {
        let pair = std::str::from_utf8(&digits[i * 2..i * 2 + 2]).unwrap();
        u8::from_str_radix(pair, 16).unwrap()
    })
}
