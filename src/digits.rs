//! Base-16 message digits and checksum.

use crate::params::{BASE16_MAX, CHAINS, DIGEST_BYTES};
use crate::signature::MessageDigest;

/// Returns 64 base-16 message digits followed by three checksum digits.
/// Each byte contributes its high nibble first; checksum digits are most significant first.
pub(crate) fn message_digits(digest: &MessageDigest) -> [u8; CHAINS] {
    // Iterate over the digest bytes in pairs
    let mut digits = [0u8; 64];
    let mut i = 0;

    let mut checksum_base10 = 0u16;

    while i < DIGEST_BYTES {
        let high_nibble = digest.as_bytes()[i] >> 4;
        let low_nibble = digest.as_bytes()[i] & 0x0f;

        // Store the digits
        digits[i * 2] = high_nibble;
        digits[i * 2 + 1] = low_nibble;

        // Compute the checksum base 10
        checksum_base10 += (BASE16_MAX - high_nibble) as u16;
        checksum_base10 += (BASE16_MAX - low_nibble) as u16;

        i += 1;
    }

    // Compute the checksum digits
    let checksum_high_digit = (checksum_base10 / 256) as u8;

    let checksum_mid_digit = (checksum_base10 % 256 / 16) as u8;

    let checksum_low_digit = (checksum_base10 % 16) as u8;

    let checksum_digits: [u8; 3] = [checksum_high_digit, checksum_mid_digit, checksum_low_digit];

    // Combine the digits into the result array
    let mut result = [0u8; CHAINS];
    result[..64].copy_from_slice(&digits);
    result[64..].copy_from_slice(&checksum_digits);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_digits_reads_high_nibble_before_low_nibble() {
        let digest = MessageDigest::from_bytes([0xa7; DIGEST_BYTES]);
        let digits = message_digits(&digest);

        assert_eq!(&digits[..2], &[10, 7]);
    }

    #[test]
    fn message_digits_preserves_message_byte_order() {
        let mut bytes = [0u8; DIGEST_BYTES];
        bytes[..3].copy_from_slice(&[0x12, 0x34, 0x56]);

        let digest = MessageDigest::from_bytes(bytes);
        let digits = message_digits(&digest);

        assert_eq!(&digits[..6], &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn message_digits_for_zero_bytes_has_checksum_three_twelve_zero() {
        let digest = MessageDigest::from_bytes([0; DIGEST_BYTES]);
        let digits = message_digits(&digest);

        // 64 * (15 - 0) = 960
        // 960 = 0x3c0 in hex
        // checksum = 3, 12, 0
        let mut expected = [0u8; 67];
        expected[64..].copy_from_slice(&[3, 12, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_maximum_bytes_has_zero_checksum() {
        let mut max_digest = [0; DIGEST_BYTES];
        max_digest.fill(0xff);
        let digest: MessageDigest = MessageDigest::from_bytes(max_digest);
        let digits = message_digits(&digest);

        // 64 * (15 - 15) = 0
        // checksum = 0, 0, 0
        let mut expected = [15u8; 67];
        expected[64..].copy_from_slice(&[0, 0, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_repeated_one_nibbles_has_checksum_three_eight_zero() {
        let all_one = [0x11; DIGEST_BYTES];
        let digest: MessageDigest = MessageDigest::from_bytes(all_one);
        let digits = message_digits(&digest);

        // 64 * (15 - 1) = 896
        // 896 = 0x380 in hex
        // checksum = 3, 8, 0
        let mut expected = [1u8; 67];
        expected[64..].copy_from_slice(&[3, 8, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_alternating_zero_and_fifteen_has_checksum_one_fourteen_zero() {
        let alternating = [0x0f; DIGEST_BYTES];
        let digest: MessageDigest = MessageDigest::from_bytes(alternating);
        let digits = message_digits(&digest);

        // Message digits alternate between 0 and 15.
        // 32 * ((15 - 0) + (15 - 15)) = 480 = 0x1e0.
        let mut expected = [0u8; 67];

        for pair in expected[..64].chunks_exact_mut(2) {
            pair.copy_from_slice(&[0, 15]);
        }

        expected[64..].copy_from_slice(&[1, 14, 0]);

        assert_eq!(digits, expected);
    }
}
