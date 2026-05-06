use chrono::{DateTime, Duration, Utc};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};
use swiyu_core::statuslist::{
    SWIYU_STATUS_LIST_BITS, SWIYU_STATUS_LIST_CAPACITY, StatusList as CoreStatusList,
};

use crate::domain::{
    BITSTRING_BYTES, IssuerId, StatusList, StatusListId, StatusListIndex, StatusValue,
};

use super::PersistenceError;
use super::helpers::integrity_from;

/// Provisions a fresh status list for an issuer and re-points the
/// issuer's `current_status_list_id` at it.
///
/// Inserts a zero-filled `status_lists` row (capacity, encoding, and
/// version counters all start from zero) and updates `issuers.
/// current_status_list_id` to the new id. Both writes happen on the
/// caller-supplied connection so an enclosing transaction can roll
/// back together with whatever else the caller is doing — the
/// issuance flow runs this inside the same transaction as the offer
/// transition.
///
/// `registry_entry_id` and `registry_url` may be `None` (the row stays
/// in the *unallocated-on-registry* state until the worker fills them
/// in) or `Some` (the issuer-creation worker has already obtained them
/// from `create_status_list_entry` and persists them alongside the
/// row). See `plan-credential-management.md` § "Eager registry-side
/// provisioning at issuer-creation time".
///
/// Returns the id of the newly provisioned list. The function does
/// **not** check the issuer exists; the FK on `status_lists.
/// issuer_id` rejects an unknown issuer at insert time.
pub async fn provision_for_issuer(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
    registry_entry_id: Option<&str>,
    registry_url: Option<&str>,
) -> Result<StatusListId, PersistenceError> {
    let new_id = StatusListId::generate();

    sqlx::query(
        r#"
        INSERT INTO status_lists (id, issuer_id, bitstring, registry_entry_id, registry_url)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(new_id.bare())
    .bind(issuer_id.bare())
    .bind(vec![0u8; BITSTRING_BYTES])
    .bind(registry_entry_id)
    .bind(registry_url)
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        r#"
        UPDATE issuers
        SET current_status_list_id = $1
        WHERE id = $2
        "#,
    )
    .bind(new_id.bare())
    .bind(issuer_id.bare())
    .execute(&mut *conn)
    .await?;

    Ok(new_id)
}

/// Reads the issuer's current status-list pointer.
///
/// Returns `Ok(None)` when the issuer has never been provisioned a
/// list (the lazy-provisioning case) **or** when the issuer does not
/// exist; the two collapse intentionally — callers in the issuance
/// path treat both as "needs provisioning" and the issuer's
/// existence is enforced separately.
pub async fn current_for_issuer(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
) -> Result<Option<StatusListId>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT current_status_list_id
        FROM issuers
        WHERE id = $1
        "#,
    )
    .bind(issuer_id.bare())
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let raw: Option<String> = row.try_get("current_status_list_id")?;
    raw.map(StatusListId::from_bare)
        .transpose()
        .map_err(integrity_from)
}

/// Reads the issuer's current status-list together with its
/// registry-side public URL.
///
/// The `registry_url` column is populated by the create_issuer worker
/// when it allocates the entry on the SWIYU Status Registry; callers in
/// the issuance path embed it verbatim into the credential's signed
/// `status.status_list.uri` claim. A list whose `registry_url` is still
/// `NULL` cannot back a publicly-resolvable credential, so the issuance
/// handler refuses to allocate against it.
///
/// Returns `Ok(None)` when the issuer has no current list **or** when
/// the issuer row does not exist; the same collapse as
/// [`current_for_issuer`].
pub async fn current_for_issuer_with_url(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
) -> Result<Option<(StatusListId, Option<String>)>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT s.id, s.registry_url
        FROM issuers i
        JOIN status_lists s ON s.id = i.current_status_list_id
        WHERE i.id = $1
        "#,
    )
    .bind(issuer_id.bare())
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let raw_id: String = row.try_get("id")?;
    let list_id = StatusListId::from_bare(raw_id).map_err(integrity_from)?;
    let registry_url: Option<String> = row.try_get("registry_url")?;
    Ok(Some((list_id, registry_url)))
}

/// Atomically allocates the next free index in the list.
///
/// Implemented as a single `UPDATE ... RETURNING` so concurrent
/// allocators on the same list serialise on the row lock and each
/// receive a distinct index. The capacity guard in the `WHERE`
/// clause turns "list is full" into a 0-row update; this surfaces as
/// `Ok(None)`, signalling the caller to provision a fresh list and
/// re-point `issuers.current_status_list_id`.
///
/// The same statement bumps `committed_version`, so the publish
/// worker observes every allocation as a dirty-list event.
///
/// Returns `Ok(None)` when the list is at capacity **or** when the
/// list id does not exist; callers in the issuance path reach for
/// provisioning in either case.
pub async fn allocate_index(
    conn: &mut PgConnection,
    list_id: &StatusListId,
) -> Result<Option<StatusListIndex>, PersistenceError> {
    let row = sqlx::query(
        r#"
        UPDATE status_lists
        SET allocated_count = allocated_count + 1,
            committed_version = committed_version + 1
        WHERE id = $1 AND allocated_count < $2
        RETURNING allocated_count - 1 AS allocated_index
        "#,
    )
    .bind(list_id.bare())
    .bind(SWIYU_STATUS_LIST_CAPACITY as i32)
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let raw: i32 = row.try_get("allocated_index")?;
    let index = u32::try_from(raw)
        .ok()
        .and_then(|value| StatusListIndex::try_from(value).ok())
        .ok_or_else(|| PersistenceError::DataIntegrity {
            details: format!("status_lists row {list_id} returned out-of-range index {raw}"),
        })?;
    Ok(Some(index))
}

/// Flips the two-bit slot at `index` in the list's bitstring to
/// `value` and bumps `committed_version`.
///
/// Reads the bitstring `FOR UPDATE` (row exclusive lock) inside the
/// caller-supplied transaction, applies the bit edit in memory via
/// the encoding helpers, then writes the full bitstring back. The
/// 32 KB read-modify-write is acceptable at v0.1.0 issuance volumes;
/// see `aspect-credential-management.md` (Bitstring read-modify-write
/// contention).
///
/// Returns `PersistenceError::NotFound` when the list does not exist.
pub async fn write_bit(
    conn: &mut PgConnection,
    list_id: &StatusListId,
    index: StatusListIndex,
    value: StatusValue,
) -> Result<(), PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT bitstring
        FROM status_lists
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(list_id.bare())
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Err(PersistenceError::NotFound);
    };
    let bitstring: Vec<u8> = row.try_get("bitstring")?;
    if bitstring.len() != BITSTRING_BYTES {
        return Err(PersistenceError::DataIntegrity {
            details: format!(
                "status_lists row {list_id} carries bitstring of unexpected length: {}",
                bitstring.len()
            ),
        });
    }

    let mut list = CoreStatusList::from_raw(SWIYU_STATUS_LIST_BITS, bitstring)
        .expect("SWIYU_STATUS_LIST_BITS is in core's accepted range");
    list.set_at(u64::from(index.value()), value)
        .map_err(|err| PersistenceError::DataIntegrity {
            details: format!("status_lists row {list_id}: {err}"),
        })?;
    let bitstring = list.as_bytes();

    sqlx::query(
        r#"
        UPDATE status_lists
        SET bitstring = $1,
            committed_version = committed_version + 1
        WHERE id = $2
        "#,
    )
    .bind(bitstring)
    .bind(list_id.bare())
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Records a successful publish round.
///
/// Conditional on `published_version < target_version`: a concurrent
/// worker that already advanced the row past `target_version` makes
/// our update a no-op (returns `Ok(false)`). On the first writer the
/// happy path resets the publish-state columns: the lease clears,
/// the error string clears, the attempt counter resets to zero.
///
/// Returns `Ok(true)` when the row was updated, `Ok(false)` when the
/// conditional `WHERE` rejected the update.
pub async fn record_publish_success(
    conn: &mut PgConnection,
    list_id: &StatusListId,
    target_version: u64,
    now: DateTime<Utc>,
) -> Result<bool, PersistenceError> {
    let target = i64::try_from(target_version).map_err(|_| PersistenceError::DataIntegrity {
        details: format!("status_lists row {list_id}: target_version overflows i64"),
    })?;
    let result = sqlx::query(
        r#"
        UPDATE status_lists
        SET published_version = $1,
            last_publish_attempt_at = $2,
            last_publish_error = NULL,
            next_publish_attempt_at = NULL,
            publish_attempts = 0
        WHERE id = $3 AND published_version < $1
        "#,
    )
    .bind(target)
    .bind(now)
    .bind(list_id.bare())
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Records a failed publish round (retryable or terminal).
///
/// Used by both the retryable and terminal paths in the publish
/// worker; they differ only in `next_attempt_at` (a short backoff vs
/// a flat long retry). The row's `last_publish_attempt_at` and
/// `last_publish_error` get the round's outcome; `publish_attempts`
/// increments by one; `next_publish_attempt_at` is the timestamp at
/// which the row becomes eligible to be re-acquired.
pub async fn record_publish_failure(
    conn: &mut PgConnection,
    list_id: &StatusListId,
    error_message: &str,
    next_attempt_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE status_lists
        SET last_publish_attempt_at = $1,
            last_publish_error = $2,
            next_publish_attempt_at = $3,
            publish_attempts = publish_attempts + 1
        WHERE id = $4
        "#,
    )
    .bind(now)
    .bind(error_message)
    .bind(next_attempt_at)
    .bind(list_id.bare())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Atomically picks the oldest dirty status list and stamps it with a
/// publish-attempt lease.
///
/// "Dirty" means `committed_version > published_version` (a bit edit
/// has landed since the last successful publish round) and the row's
/// `next_publish_attempt_at` is either NULL (never tried) or has
/// already passed (a previous lease expired). The query uses
/// `FOR UPDATE SKIP LOCKED` so a future split into multiple publish
/// workers does not require schema or query changes; for v0.1.0 there
/// is one worker, but the convention matches `operation_tasks::
/// acquire_next`.
///
/// `lease_duration` controls how long another worker waits before
/// re-picking the row on crash recovery. The plan calls out 30s as a
/// reasonable starting point; tune via observed publish round
/// durations once metrics land.
///
/// Returns `Ok(None)` when no dirty list is currently runnable.
pub async fn acquire_next_dirty(
    conn: &mut PgConnection,
    now: DateTime<Utc>,
    lease_duration: Duration,
) -> Result<Option<StatusList>, PersistenceError> {
    let lease_expiry = now + lease_duration;
    let row = sqlx::query(
        r#"
        UPDATE status_lists
        SET next_publish_attempt_at = $1
        WHERE id = (
            SELECT id FROM status_lists
            WHERE committed_version > published_version
              AND (next_publish_attempt_at IS NULL OR next_publish_attempt_at <= $2)
            ORDER BY next_publish_attempt_at NULLS FIRST, created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, issuer_id, bitstring, allocated_count,
                  committed_version, published_version,
                  last_publish_attempt_at, last_publish_error,
                  next_publish_attempt_at, publish_attempts,
                  created_at, registry_entry_id, registry_url
        "#,
    )
    .bind(lease_expiry)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;

    row.as_ref().map(row_to_status_list).transpose()
}

fn row_to_status_list(row: &PgRow) -> Result<StatusList, PersistenceError> {
    let id: String = row.try_get("id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let bitstring: Vec<u8> = row.try_get("bitstring")?;
    let allocated_count: i32 = row.try_get("allocated_count")?;
    let committed_version: i64 = row.try_get("committed_version")?;
    let published_version: i64 = row.try_get("published_version")?;
    let last_publish_attempt_at: Option<DateTime<Utc>> = row.try_get("last_publish_attempt_at")?;
    let last_publish_error: Option<String> = row.try_get("last_publish_error")?;
    let next_publish_attempt_at: Option<DateTime<Utc>> = row.try_get("next_publish_attempt_at")?;
    let publish_attempts: i32 = row.try_get("publish_attempts")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let registry_entry_id: Option<String> = row.try_get("registry_entry_id")?;
    let registry_url: Option<String> = row.try_get("registry_url")?;

    if bitstring.len() != BITSTRING_BYTES {
        return Err(PersistenceError::DataIntegrity {
            details: format!(
                "status_lists row {id} carries bitstring of unexpected length: {}",
                bitstring.len()
            ),
        });
    }

    let allocated_count =
        u32::try_from(allocated_count).map_err(|_| PersistenceError::DataIntegrity {
            details: format!("status_lists row {id} has negative allocated_count"),
        })?;
    let committed_version =
        u64::try_from(committed_version).map_err(|_| PersistenceError::DataIntegrity {
            details: format!("status_lists row {id} has negative committed_version"),
        })?;
    let published_version =
        u64::try_from(published_version).map_err(|_| PersistenceError::DataIntegrity {
            details: format!("status_lists row {id} has negative published_version"),
        })?;
    let publish_attempts =
        u32::try_from(publish_attempts).map_err(|_| PersistenceError::DataIntegrity {
            details: format!("status_lists row {id} has negative publish_attempts"),
        })?;

    Ok(StatusList {
        id: StatusListId::from_bare(id).map_err(integrity_from)?,
        issuer_id: IssuerId::from_bare(issuer_id).map_err(integrity_from)?,
        bitstring,
        allocated_count,
        committed_version,
        published_version,
        last_publish_attempt_at,
        last_publish_error,
        next_publish_attempt_at,
        publish_attempts,
        created_at,
        registry_entry_id,
        registry_url,
    })
}
