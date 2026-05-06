use super::{BITSTRING_BYTES, STATUS_SIZE_BITS, StatusListIndex, StatusValue};
use crate::domain::DomainError;

// Position of credential `index`'s two-bit slot inside the bitstring.
//
// Layout follows the W3C BitstringStatusList convention: the first
// credential occupies the most-significant bits of byte 0, the next
// credential the bits below it, and so on. With STATUS_SIZE_BITS = 2
// each byte therefore carries four credentials:
//
//   byte[N] = | idx 4N (bits 7..6) | idx 4N+1 (5..4) | idx 4N+2 (3..2) | idx 4N+3 (1..0) |
fn slot(index: StatusListIndex) -> (usize, u8) {
    let i = index.value() as usize;
    let entries_per_byte = (8 / STATUS_SIZE_BITS) as usize;
    let byte_idx = i / entries_per_byte;
    let sub = (i % entries_per_byte) as u8;
    let shift = 8 - STATUS_SIZE_BITS - sub * STATUS_SIZE_BITS;
    (byte_idx, shift)
}

pub fn read_status(bitstring: &[u8], index: StatusListIndex) -> Result<StatusValue, DomainError> {
    debug_assert_eq!(bitstring.len(), BITSTRING_BYTES);
    let (byte_idx, shift) = slot(index);
    let mask = (1u8 << STATUS_SIZE_BITS) - 1;
    let raw = (bitstring[byte_idx] >> shift) & mask;
    StatusValue::try_from(raw)
}

pub fn write_status(bitstring: &mut [u8], index: StatusListIndex, value: StatusValue) {
    debug_assert_eq!(bitstring.len(), BITSTRING_BYTES);
    let (byte_idx, shift) = slot(index);
    let mask = (1u8 << STATUS_SIZE_BITS) - 1;
    let cleared = bitstring[byte_idx] & !(mask << shift);
    bitstring[byte_idx] = cleared | ((value as u8) << shift);
}

#[cfg(test)]
mod tests {
    use super::super::LIST_CAPACITY;
    use super::*;

    fn empty_bitstring() -> Vec<u8> {
        vec![0u8; BITSTRING_BYTES]
    }

    fn idx(i: u32) -> StatusListIndex {
        StatusListIndex::try_from(i).unwrap()
    }

    #[test]
    fn empty_bitstring_reads_valid_everywhere() {
        let bitstring = empty_bitstring();
        for i in [0u32, 1, 2, 3, 4, 1000, LIST_CAPACITY - 1] {
            assert_eq!(read_status(&bitstring, idx(i)).unwrap(), StatusValue::Valid);
        }
    }

    #[test]
    fn write_revoked_at_index_zero_sets_top_two_bits() {
        let mut bitstring = empty_bitstring();
        write_status(&mut bitstring, idx(0), StatusValue::Revoked);
        assert_eq!(bitstring[0], 0b1000_0000);
    }

    #[test]
    fn write_suspended_at_index_zero_sets_bit_six() {
        let mut bitstring = empty_bitstring();
        write_status(&mut bitstring, idx(0), StatusValue::Suspended);
        assert_eq!(bitstring[0], 0b0100_0000);
    }

    #[test]
    fn first_four_credentials_share_byte_zero() {
        // Place a different value at each sub-position of byte 0:
        // idx 0 = Revoked   (0b10) → bits 7..6 = 10
        // idx 1 = Suspended (0b01) → bits 5..4 = 01
        // idx 2 = Revoked   (0b10) → bits 3..2 = 10
        // idx 3 = Suspended (0b01) → bits 1..0 = 01
        // Byte 0 = 1001 1001 = 0x99
        let mut bitstring = empty_bitstring();
        write_status(&mut bitstring, idx(0), StatusValue::Revoked);
        write_status(&mut bitstring, idx(1), StatusValue::Suspended);
        write_status(&mut bitstring, idx(2), StatusValue::Revoked);
        write_status(&mut bitstring, idx(3), StatusValue::Suspended);
        assert_eq!(bitstring[0], 0b1001_1001);
        // The next byte stays untouched.
        assert_eq!(bitstring[1], 0);
    }

    #[test]
    fn fifth_credential_starts_byte_one() {
        let mut bitstring = empty_bitstring();
        write_status(&mut bitstring, idx(4), StatusValue::Revoked);
        assert_eq!(bitstring[0], 0);
        assert_eq!(bitstring[1], 0b1000_0000);
    }

    #[test]
    fn last_credential_lands_in_last_byte() {
        let mut bitstring = empty_bitstring();
        write_status(&mut bitstring, idx(LIST_CAPACITY - 1), StatusValue::Revoked);
        assert_eq!(bitstring[BITSTRING_BYTES - 1], 0b0000_0010);
        assert_eq!(bitstring[BITSTRING_BYTES - 2], 0);
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut bitstring = empty_bitstring();
        let cases = [
            (0u32, StatusValue::Valid),
            (1, StatusValue::Revoked),
            (2, StatusValue::Suspended),
            (3, StatusValue::Revoked),
            (4, StatusValue::Suspended),
            (100, StatusValue::Revoked),
            (LIST_CAPACITY - 1, StatusValue::Suspended),
        ];
        for (i, value) in cases {
            write_status(&mut bitstring, idx(i), value);
        }
        for (i, value) in cases {
            assert_eq!(read_status(&bitstring, idx(i)).unwrap(), value);
        }
    }

    #[test]
    fn write_overwrites_previous_value_at_same_index() {
        let mut bitstring = empty_bitstring();
        write_status(&mut bitstring, idx(7), StatusValue::Revoked);
        assert_eq!(
            read_status(&bitstring, idx(7)).unwrap(),
            StatusValue::Revoked
        );
        write_status(&mut bitstring, idx(7), StatusValue::Suspended);
        assert_eq!(
            read_status(&bitstring, idx(7)).unwrap(),
            StatusValue::Suspended
        );
        write_status(&mut bitstring, idx(7), StatusValue::Valid);
        assert_eq!(read_status(&bitstring, idx(7)).unwrap(), StatusValue::Valid);
    }

    #[test]
    fn write_does_not_disturb_neighbours() {
        let mut bitstring = empty_bitstring();
        // Set every index in byte 0 to a non-zero value.
        write_status(&mut bitstring, idx(0), StatusValue::Suspended);
        write_status(&mut bitstring, idx(1), StatusValue::Revoked);
        write_status(&mut bitstring, idx(2), StatusValue::Suspended);
        write_status(&mut bitstring, idx(3), StatusValue::Revoked);
        let before = bitstring[0];

        // Rewrite only index 1; the other three slots must keep their values.
        write_status(&mut bitstring, idx(1), StatusValue::Valid);
        assert_eq!(
            read_status(&bitstring, idx(0)).unwrap(),
            StatusValue::Suspended
        );
        assert_eq!(read_status(&bitstring, idx(1)).unwrap(), StatusValue::Valid);
        assert_eq!(
            read_status(&bitstring, idx(2)).unwrap(),
            StatusValue::Suspended
        );
        assert_eq!(
            read_status(&bitstring, idx(3)).unwrap(),
            StatusValue::Revoked
        );
        assert_ne!(bitstring[0], before);
    }

    #[test]
    fn read_invalid_value_three_returns_error() {
        // Synthesise a bitstring carrying the unused value `3` at index 0.
        let mut bitstring = empty_bitstring();
        bitstring[0] = 0b1100_0000;
        assert!(read_status(&bitstring, idx(0)).is_err());
    }

    #[test]
    fn round_trip_at_every_sub_position_of_a_byte() {
        // Property-style coverage of the bit-shift arithmetic: for each
        // sub-position of byte N, every value round-trips cleanly.
        for byte in 0usize..4 {
            for sub in 0u32..4 {
                let i = (byte as u32) * 4 + sub;
                for value in [
                    StatusValue::Valid,
                    StatusValue::Suspended,
                    StatusValue::Revoked,
                ] {
                    let mut bitstring = empty_bitstring();
                    write_status(&mut bitstring, idx(i), value);
                    assert_eq!(
                        read_status(&bitstring, idx(i)).unwrap(),
                        value,
                        "round-trip failed at byte {byte} sub {sub} value {value:?}"
                    );
                }
            }
        }
    }
}
