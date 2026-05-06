use chrono::{DateTime, Utc};

use super::DomainError;
use super::ids::{IssuerId, StatusListId};

pub mod encoding;

/// Bits per credential in the BitstringStatusList encoding.
///
/// `2` accommodates the three values [`StatusValue::Valid`],
/// [`StatusValue::Suspended`], [`StatusValue::Revoked`] in a single
/// list. See `aspect-credential-management.md` (Status-list
/// integration / Bit encoding) and
/// `impl-credential-management.md` (Domain types).
pub const STATUS_SIZE_BITS: u8 = 2;

/// Maximum number of credentials a single status list can carry.
///
/// `131_072` is the standard BitstringStatusList capacity. When this
/// is exhausted, the issuance path provisions a fresh status list and
/// re-points `issuers.current_status_list_id`.
pub const LIST_CAPACITY: u32 = 131_072;

/// Length in bytes of the raw bitstring backing one status list.
///
/// `LIST_CAPACITY * STATUS_SIZE_BITS / 8` = `32_768`. The persistence
/// layer enforces this length via a CHECK constraint on the
/// `status_lists.bitstring` column.
pub const BITSTRING_BYTES: usize = (LIST_CAPACITY as usize) * (STATUS_SIZE_BITS as usize) / 8;

/// Per-credential value stored in a BitstringStatusList entry.
///
/// The discriminants are the wire-format bit values:
/// `0` = valid, `1` = suspended, `2` = revoked. Value `3` is unused
/// and surfaced as [`DomainError::InvalidInput`] from the encoding
/// helpers if encountered on read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusValue {
    Valid = 0,
    Suspended = 1,
    Revoked = 2,
}

impl TryFrom<u8> for StatusValue {
    type Error = DomainError;

    fn try_from(raw: u8) -> Result<Self, Self::Error> {
        match raw {
            0 => Ok(Self::Valid),
            1 => Ok(Self::Suspended),
            2 => Ok(Self::Revoked),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown status value: {raw}"),
            }),
        }
    }
}

/// Position of a credential within a status list, bounded by
/// [`LIST_CAPACITY`].
///
/// The constructor enforces the bound; the encoding helpers and
/// persistence layer rely on the type-level guarantee that the value
/// is within range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusListIndex(u32);

impl StatusListIndex {
    pub fn value(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for StatusListIndex {
    type Error = DomainError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= LIST_CAPACITY {
            return Err(DomainError::InvalidInput {
                details: format!(
                    "status list index out of range: {value} (capacity = {LIST_CAPACITY})"
                ),
            });
        }
        Ok(Self(value))
    }
}

impl std::fmt::Display for StatusListIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One BitstringStatusList instance owned by an issuer.
///
/// `committed_version` increments on every committed bit update
/// (issuance or lifecycle op). `published_version` increments after a
/// successful publish round to the SWIYU Status Registry. The
/// difference drives the publish worker's "is this list dirty?"
/// probe; see `aspect-credential-management.md` (Asynchronous
/// execution / Phase 2).
#[derive(Debug, Clone)]
pub struct StatusList {
    pub id: StatusListId,
    pub issuer_id: IssuerId,

    /// Raw bitstring; length is exactly [`BITSTRING_BYTES`].
    pub bitstring: Vec<u8>,

    /// Number of indices already handed out by the issuance path.
    /// The next free index is `allocated_count`. Once it reaches
    /// [`LIST_CAPACITY`] a fresh status list is provisioned.
    pub allocated_count: u32,

    pub committed_version: u64,
    pub published_version: u64,

    pub last_publish_attempt_at: Option<DateTime<Utc>>,
    pub last_publish_error: Option<String>,
    pub next_publish_attempt_at: Option<DateTime<Utc>>,
    pub publish_attempts: u32,

    pub created_at: DateTime<Utc>,
}

impl StatusList {
    /// Constructs a fresh, empty status list. All bits zeroed
    /// (every entry reads as [`StatusValue::Valid`]); both version
    /// counters start at zero.
    pub fn new(issuer_id: IssuerId, now: DateTime<Utc>) -> Self {
        Self {
            id: StatusListId::generate(),
            issuer_id,
            bitstring: vec![0u8; BITSTRING_BYTES],
            allocated_count: 0,
            committed_version: 0,
            published_version: 0,
            last_publish_attempt_at: None,
            last_publish_error: None,
            next_publish_attempt_at: None,
            publish_attempts: 0,
            created_at: now,
        }
    }

    pub fn is_at_capacity(&self) -> bool {
        self.allocated_count >= LIST_CAPACITY
    }

    pub fn is_dirty(&self) -> bool {
        self.committed_version > self.published_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_list() -> StatusList {
        StatusList::new(IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap(), Utc::now())
    }

    #[test]
    fn constants_are_self_consistent() {
        assert_eq!(
            BITSTRING_BYTES,
            (LIST_CAPACITY as usize) * (STATUS_SIZE_BITS as usize) / 8
        );
        assert_eq!(BITSTRING_BYTES, 32_768);
    }

    #[test]
    fn new_list_has_zero_bitstring_and_zero_versions() {
        let list = make_list();
        assert_eq!(list.bitstring.len(), BITSTRING_BYTES);
        assert!(list.bitstring.iter().all(|b| *b == 0));
        assert_eq!(list.allocated_count, 0);
        assert_eq!(list.committed_version, 0);
        assert_eq!(list.published_version, 0);
    }

    #[test]
    fn is_at_capacity_only_at_full() {
        let mut list = make_list();
        assert!(!list.is_at_capacity());
        list.allocated_count = LIST_CAPACITY - 1;
        assert!(!list.is_at_capacity());
        list.allocated_count = LIST_CAPACITY;
        assert!(list.is_at_capacity());
    }

    #[test]
    fn is_dirty_when_committed_ahead_of_published() {
        let mut list = make_list();
        assert!(!list.is_dirty());
        list.committed_version = 1;
        assert!(list.is_dirty());
        list.published_version = 1;
        assert!(!list.is_dirty());
    }

    #[test]
    fn status_value_try_from_round_trip() {
        for value in [
            StatusValue::Valid,
            StatusValue::Suspended,
            StatusValue::Revoked,
        ] {
            assert_eq!(StatusValue::try_from(value as u8).unwrap(), value);
        }
    }

    #[test]
    fn status_value_try_from_rejects_three() {
        assert!(StatusValue::try_from(3u8).is_err());
        assert!(StatusValue::try_from(255u8).is_err());
    }

    #[test]
    fn status_list_index_rejects_out_of_range() {
        assert!(StatusListIndex::try_from(LIST_CAPACITY).is_err());
        assert!(StatusListIndex::try_from(LIST_CAPACITY + 1).is_err());
        assert!(StatusListIndex::try_from(u32::MAX).is_err());
    }

    #[test]
    fn status_list_index_accepts_in_range() {
        assert_eq!(StatusListIndex::try_from(0u32).unwrap().value(), 0);
        assert_eq!(
            StatusListIndex::try_from(LIST_CAPACITY - 1)
                .unwrap()
                .value(),
            LIST_CAPACITY - 1
        );
    }
}
