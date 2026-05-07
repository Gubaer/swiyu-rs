use chrono::{DateTime, Utc};
use swiyu_core::statuslist::{SWIYU_STATUS_LIST_BITS, SWIYU_STATUS_LIST_CAPACITY};

use super::DomainError;
use super::ids::{IssuerId, StatusListId};

pub mod wrapper;

pub use swiyu_core::statuslist::StatusValue;

/// Length in bytes of the raw bitstring backing one status list.
///
/// Derived from the SWIYU profile in `swiyu-core` (`SWIYU_STATUS_LIST_CAPACITY *
/// SWIYU_STATUS_LIST_BITS / 8` = `32_768`). The persistence layer enforces this
/// length via a CHECK constraint on the `status_lists.bitstring` column.
pub const BITSTRING_BYTES: usize =
    (SWIYU_STATUS_LIST_CAPACITY as usize) * (SWIYU_STATUS_LIST_BITS as usize) / 8;

/// Position of a credential within a status list, bounded by
/// `SWIYU_STATUS_LIST_CAPACITY`.
///
/// `TryFrom<u32>` enforces the bound; the persistence layer relies on
/// the type-level guarantee that the value is within range.
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
        if u64::from(value) >= SWIYU_STATUS_LIST_CAPACITY {
            return Err(DomainError::InvalidInput {
                details: format!(
                    "status list index out of range: {value} (capacity = {SWIYU_STATUS_LIST_CAPACITY})"
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

/// One status list owned by an issuer.
#[derive(Debug, Clone)]
pub struct StatusList {
    pub id: StatusListId,
    pub issuer_id: IssuerId,

    /// Raw bitstring; length is exactly [`BITSTRING_BYTES`].
    pub bitstring: Vec<u8>,

    /// Number of indices already handed out by the issuance path.
    /// The next free index is `allocated_count`. Once it reaches
    /// `SWIYU_STATUS_LIST_CAPACITY` a fresh status list is provisioned.
    pub allocated_count: u32,

    /// Increments on every committed bit update (issuance or lifecycle op).
    /// The difference from `published_version` drives the publish worker's
    /// "is this list dirty?" probe.
    pub committed_version: u64,
    /// Increments after a successful publish round to the SWIYU Status Registry.
    pub published_version: u64,

    pub last_publish_attempt_at: Option<DateTime<Utc>>,
    pub last_publish_error: Option<String>,
    pub next_publish_attempt_at: Option<DateTime<Utc>>,
    pub publish_attempts: u32,

    pub created_at: DateTime<Utc>,

    /// Registry-side entry UUID. `None` until provisioned; used as the path
    /// segment of every subsequent status-list update request.
    pub registry_entry_id: Option<String>,

    /// URL returned by the registry alongside `registry_entry_id`. Embedded
    /// as the `uri` in every issued credential's status claim and as the `sub`
    /// of the published `statuslist+jwt`. `None` until provisioned; a list
    /// without this cannot back a verifier-dereferenceable credential.
    pub registry_url: Option<String>,
}

impl StatusList {
    /// Constructs a fresh, empty status list. All bits zeroed
    /// (every entry reads as [`StatusValue::Valid`]); both version
    /// counters start at zero; both registry coordinates start as
    /// `None` and are filled in after the issuer-creation operation
    /// task talks to the SWIYU Status Registry.
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
            registry_entry_id: None,
            registry_url: None,
        }
    }

    pub fn is_at_capacity(&self) -> bool {
        u64::from(self.allocated_count) >= SWIYU_STATUS_LIST_CAPACITY
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
    fn bitstring_bytes_matches_swiyu_profile() {
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
    fn new_list_has_unallocated_registry_coords() {
        let list = make_list();
        assert!(list.registry_entry_id.is_none());
        assert!(list.registry_url.is_none());
    }

    #[test]
    fn is_at_capacity_only_at_full() {
        let mut list = make_list();
        assert!(!list.is_at_capacity());
        list.allocated_count = (SWIYU_STATUS_LIST_CAPACITY - 1) as u32;
        assert!(!list.is_at_capacity());
        list.allocated_count = SWIYU_STATUS_LIST_CAPACITY as u32;
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
    fn status_list_index_rejects_out_of_range() {
        let cap = SWIYU_STATUS_LIST_CAPACITY as u32;
        assert!(StatusListIndex::try_from(cap).is_err());
        assert!(StatusListIndex::try_from(cap + 1).is_err());
        assert!(StatusListIndex::try_from(u32::MAX).is_err());
    }

    #[test]
    fn status_list_index_accepts_in_range() {
        let cap = SWIYU_STATUS_LIST_CAPACITY as u32;
        assert_eq!(StatusListIndex::try_from(0u32).unwrap().value(), 0);
        assert_eq!(StatusListIndex::try_from(cap - 1).unwrap().value(), cap - 1);
    }
}
