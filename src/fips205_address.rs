//! The FIPS 205 address layout (section 4.2) shared by FORS and SLH-DSA.
//!
//! An address labels one hash call, so no two calls in a key hash the same input.
//! FORS and SLH-DSA build each kind of address in one named constructor on top of
//! [`encode`], so a constructor never inherits fields from an address of another type.

/// FIPS 205 section 4.2 address types.
pub(crate) const WOTS_HASH: u32 = 0;
pub(crate) const WOTS_PK: u32 = 1;
pub(crate) const TREE: u32 = 2;
pub(crate) const FORS_TREE: u32 = 3;
pub(crate) const FORS_ROOTS: u32 = 4;
pub(crate) const WOTS_PRF: u32 = 5;
pub(crate) const FORS_PRF: u32 = 6;

/// Encodes an address with big-endian fields. Words 6 and 7 are the chain and hash
/// step for WOTS+ hash addresses, and the height and index for tree addresses. The
/// tree index fills the low 8 bytes of its 12-byte field, since FIPS 205 trees never
/// need more than 64 bits.
pub(crate) fn encode(
    layer: u32,
    tree: u64,
    address_type: u32,
    key_pair: u32,
    word_6: u32,
    word_7: u32,
) -> [u8; 32] {
    //  bytes:  0..4  | 4..16 | 16..20 | 20..24   | 24..28 | 28..32
    //          layer | tree  | type   | key pair | word 6 | word 7
    let mut address = [0u8; 32];

    address[0..4].copy_from_slice(&layer.to_be_bytes());
    address[8..16].copy_from_slice(&tree.to_be_bytes());
    address[16..20].copy_from_slice(&address_type.to_be_bytes());
    address[20..24].copy_from_slice(&key_pair.to_be_bytes());
    address[24..28].copy_from_slice(&word_6.to_be_bytes());
    address[28..32].copy_from_slice(&word_7.to_be_bytes());

    address
}

/// FIPS 205 section 11.2: ADRSc = ADRS[3] || ADRS[8..16] || ADRS[19] || ADRS[20..32].
/// It drops the high bytes of the layer, tree, and type fields, which are zero in
/// every address built here: layers and types are below 256, and trees fit 64 bits.
pub(crate) fn compress(address: &[u8; 32]) -> [u8; 22] {
    let mut compressed = [0u8; 22];
    compressed[0] = address[3];
    compressed[1..9].copy_from_slice(&address[8..16]);
    compressed[9] = address[19];
    compressed[10..22].copy_from_slice(&address[20..32]);
    compressed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::hex;

    #[test]
    fn encode_places_each_field_big_endian_in_its_own_bytes() {
        let address = encode(
            0x0102_0304,
            0x0506_0708_090a_0b0c,
            0x0d0e_0f10,
            0x1112_1314,
            0x1516_1718,
            0x191a_1b1c,
        );

        assert_eq!(
            address,
            hex("01020304 00000000 05060708 090a0b0c 0d0e0f10 11121314 15161718 191a1b1c")
        );
    }

    #[test]
    fn compression_keeps_the_low_layer_tree_and_type_bytes_and_every_later_field() {
        let address = encode(16, u64::MAX, FORS_TREE, 0x0a0b_0c0d, 4, 1);

        assert_eq!(
            compress(&address),
            hex("10 ffffffffffffffff 03 0a0b0c0d 00000004 00000001")
        );
    }

    #[test]
    fn address_types_follow_fips_205_section_4_2() {
        assert_eq!(
            [
                WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
    }
}
