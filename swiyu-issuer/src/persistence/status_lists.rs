use sqlx::Row;
use sqlx::postgres::PgConnection;

use crate::domain::{
    BITSTRING_BYTES, IssuerId, LIST_CAPACITY, StatusListId, StatusListIndex, StatusValue,
    status_list::encoding,
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
/// Returns the id of the newly provisioned list. The function does
/// **not** check the issuer exists; the FK on `status_lists.
/// issuer_id` rejects an unknown issuer at insert time.
pub async fn provision_for_issuer(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
) -> Result<StatusListId, PersistenceError> {
    let new_id = StatusListId::generate();

    sqlx::query(
        r#"
        INSERT INTO status_lists (id, issuer_id, bitstring)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(new_id.bare())
    .bind(issuer_id.bare())
    .bind(vec![0u8; BITSTRING_BYTES])
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
    .bind(LIST_CAPACITY as i32)
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
    let mut bitstring: Vec<u8> = row.try_get("bitstring")?;
    if bitstring.len() != BITSTRING_BYTES {
        return Err(PersistenceError::DataIntegrity {
            details: format!(
                "status_lists row {list_id} carries bitstring of unexpected length: {}",
                bitstring.len()
            ),
        });
    }

    encoding::write_status(&mut bitstring, index, value);

    sqlx::query(
        r#"
        UPDATE status_lists
        SET bitstring = $1,
            committed_version = committed_version + 1
        WHERE id = $2
        "#,
    )
    .bind(&bitstring)
    .bind(list_id.bare())
    .execute(&mut *conn)
    .await?;

    Ok(())
}
