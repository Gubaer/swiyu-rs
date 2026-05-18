use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgConnection;
use sqlx::postgres::PgRow;
use sqlx::postgres::types::PgInterval;

use crate::domain::{CredentialType, CredentialTypeId, RevocationMode, TenantId};

use super::PersistenceError;
use super::helpers::map_database_error;

pub use super::ListPage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated,
    NotFound,
}

/// Optional updates to the structured (non-blob) columns of a
/// `credential_types` row. `None` keeps the current value; `Some`
/// writes the new value.
///
/// `display`, `claim_schema`, and `claims` are blobs handled by the
/// per-blob updaters; they are not part of this struct.
#[derive(Debug, Default)]
pub struct StructuredUpdate<'a> {
    pub vct: Option<&'a str>,
    pub internal_description: Option<&'a str>,
    pub claim_schema_source_url: Option<&'a str>,
    pub default_validity_duration: Option<Duration>,
    pub revocation_mode: Option<RevocationMode>,
}

#[derive(Debug)]
pub struct ListPageQuery {
    /// `(created_at, id)` of the last item of the previous page; `None`
    /// requests the first page. Ordering is `(created_at DESC, id DESC)`.
    pub cursor: Option<(DateTime<Utc>, String)>,
    pub limit: u32,
    /// When `false`, retired rows are filtered out — the hot path the
    /// `credential_types_tenant_active` partial index serves. When
    /// `true`, retired rows are included so admin tooling can list
    /// the historical catalogue.
    pub include_retired: bool,
}

pub async fn insert(
    conn: &mut PgConnection,
    credential_type: &CredentialType,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO credential_types (
            id, tenant_id, vct,
            display, internal_description,
            claim_schema, claim_schema_source_url, claim_schema_fetched_at,
            claims,
            default_validity_duration, revocation_mode,
            created_at, updated_at, retired_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#,
    )
    .bind(&credential_type.id)
    .bind(&credential_type.tenant_id)
    .bind(&credential_type.vct)
    .bind(&credential_type.display)
    .bind(credential_type.internal_description.as_deref())
    .bind(&credential_type.claim_schema)
    .bind(credential_type.claim_schema_source_url.as_deref())
    .bind(credential_type.claim_schema_fetched_at)
    .bind(&credential_type.claims)
    .bind(credential_type.default_validity_duration)
    .bind(credential_type.revocation_mode)
    .bind(credential_type.created_at)
    .bind(credential_type.updated_at)
    .bind(credential_type.retired_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

/// Loads a credential type by id alone (no tenant scope).
///
/// Returns retired rows verbatim; the caller is responsible for
/// filtering on `retired_at` when the "active only" predicate
/// applies.
pub async fn find_by_id(
    conn: &mut PgConnection,
    credential_type_id: &CredentialTypeId,
) -> Result<Option<CredentialType>, PersistenceError> {
    let row = sqlx::query(SELECT_ALL_COLUMNS)
        .bind(credential_type_id)
        .fetch_optional(conn)
        .await?;
    match row {
        Some(row) => Ok(Some(row_to_credential_type(&row)?)),
        None => Ok(None),
    }
}

/// Tenant-scoped variant of [`find_by_id`].
///
/// "Wrong tenant" collapses to `Ok(None)` so the lookup cannot be
/// used to probe credential-type existence across tenants.
pub async fn find_by_id_for_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_type_id: &CredentialTypeId,
) -> Result<Option<CredentialType>, PersistenceError> {
    let row = sqlx::query(SELECT_ALL_COLUMNS_FOR_TENANT)
        .bind(credential_type_id)
        .bind(tenant_id)
        .fetch_optional(conn)
        .await?;
    match row {
        Some(row) => Ok(Some(row_to_credential_type(&row)?)),
        None => Ok(None),
    }
}

pub async fn list(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    query: ListPageQuery,
) -> Result<ListPage<CredentialType>, PersistenceError> {
    let (cursor_created_at, cursor_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let limit_plus_one = i64::from(query.limit) + 1;

    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, vct,
               display, internal_description,
               claim_schema, claim_schema_source_url, claim_schema_fetched_at,
               claims,
               default_validity_duration, revocation_mode,
               created_at, updated_at, retired_at
        FROM credential_types
        WHERE tenant_id = $1
          AND ($2::bool OR retired_at IS NULL)
          AND ($3::TIMESTAMPTZ IS NULL OR (created_at, id) < ($3, $4))
        ORDER BY created_at DESC, id DESC
        LIMIT $5
        "#,
    )
    .bind(tenant_id)
    .bind(query.include_retired)
    .bind(cursor_created_at)
    .bind(cursor_id.as_deref())
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let mut items: Vec<CredentialType> = rows
        .iter()
        .map(row_to_credential_type)
        .collect::<Result<_, _>>()?;

    let has_more = items.len() as i64 > i64::from(query.limit);
    if has_more {
        items.pop();
    }

    Ok(ListPage { items, has_more })
}

/// Applies a partial update to the structured (non-blob) columns and
/// stamps `updated_at = NOW()`.
///
/// Calling with every field `None` is a valid no-op; the row's
/// `updated_at` is still bumped, since a PATCH call itself counts as
/// an edit event.
pub async fn update_structured(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_type_id: &CredentialTypeId,
    update: StructuredUpdate<'_>,
) -> Result<UpdateOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_types
        SET vct                       = COALESCE($3, vct),
            internal_description      = COALESCE($4, internal_description),
            claim_schema_source_url   = COALESCE($5, claim_schema_source_url),
            default_validity_duration = COALESCE($6, default_validity_duration),
            revocation_mode           = COALESCE($7, revocation_mode),
            updated_at                = NOW()
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_type_id)
    .bind(tenant_id)
    .bind(update.vct)
    .bind(update.internal_description)
    .bind(update.claim_schema_source_url)
    .bind(update.default_validity_duration)
    .bind(update.revocation_mode)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        Ok(UpdateOutcome::NotFound)
    } else {
        Ok(UpdateOutcome::Updated)
    }
}

/// Bumps both `claim_schema_fetched_at` and `updated_at` to `NOW()`
/// (the other blob updaters bump only `updated_at`). The caller must
/// have verified the document compiles as a JSON Schema; this helper
/// does no validation.
pub async fn update_blob_schema(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_type_id: &CredentialTypeId,
    schema: &Value,
) -> Result<UpdateOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_types
        SET claim_schema             = $3,
            claim_schema_fetched_at  = NOW(),
            updated_at               = NOW()
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_type_id)
    .bind(tenant_id)
    .bind(schema)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        Ok(UpdateOutcome::NotFound)
    } else {
        Ok(UpdateOutcome::Updated)
    }
}

pub async fn update_blob_display(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_type_id: &CredentialTypeId,
    display: &Value,
) -> Result<UpdateOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_types
        SET display    = $3,
            updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_type_id)
    .bind(tenant_id)
    .bind(display)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        Ok(UpdateOutcome::NotFound)
    } else {
        Ok(UpdateOutcome::Updated)
    }
}

pub async fn update_blob_claims(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_type_id: &CredentialTypeId,
    claims: &Value,
) -> Result<UpdateOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_types
        SET claims     = $3,
            updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_type_id)
    .bind(tenant_id)
    .bind(claims)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        Ok(UpdateOutcome::NotFound)
    } else {
        Ok(UpdateOutcome::Updated)
    }
}

/// Soft-deletes the credential type and hard-deletes every assignment
/// row pointing at it. Both statements run on the supplied connection;
/// the caller controls the surrounding transaction so retirement is
/// atomic with the assignment cascade.
///
/// A second retire call refreshes `retired_at` and `updated_at` on
/// the row and is a no-op on the (already-empty) assignment set.
pub async fn retire(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_type_id: &CredentialTypeId,
    now: DateTime<Utc>,
) -> Result<UpdateOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_types
        SET retired_at = $3,
            updated_at = $3
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_type_id)
    .bind(tenant_id)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    if result.rows_affected() == 0 {
        return Ok(UpdateOutcome::NotFound);
    }

    sqlx::query(
        r#"
        DELETE FROM issuer_credential_types
        WHERE credential_type_id = $1
        "#,
    )
    .bind(credential_type_id)
    .execute(&mut *conn)
    .await?;

    Ok(UpdateOutcome::Updated)
}

const SELECT_ALL_COLUMNS: &str = r#"
    SELECT id, tenant_id, vct,
           display, internal_description,
           claim_schema, claim_schema_source_url, claim_schema_fetched_at,
           claims,
           default_validity_duration, revocation_mode,
           created_at, updated_at, retired_at
    FROM credential_types
    WHERE id = $1
"#;

const SELECT_ALL_COLUMNS_FOR_TENANT: &str = r#"
    SELECT id, tenant_id, vct,
           display, internal_description,
           claim_schema, claim_schema_source_url, claim_schema_fetched_at,
           claims,
           default_validity_duration, revocation_mode,
           created_at, updated_at, retired_at
    FROM credential_types
    WHERE id = $1 AND tenant_id = $2
"#;

fn row_to_credential_type(row: &PgRow) -> Result<CredentialType, PersistenceError> {
    let pg_interval: PgInterval = row.try_get("default_validity_duration")?;
    let default_validity_duration = pg_interval_to_duration(pg_interval)?;

    Ok(CredentialType {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        vct: row.try_get("vct")?,
        display: row.try_get("display")?,
        internal_description: row.try_get("internal_description")?,
        claim_schema: row.try_get("claim_schema")?,
        claim_schema_source_url: row.try_get("claim_schema_source_url")?,
        claim_schema_fetched_at: row.try_get("claim_schema_fetched_at")?,
        claims: row.try_get("claims")?,
        default_validity_duration,
        revocation_mode: row.try_get("revocation_mode")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        retired_at: row.try_get("retired_at")?,
    })
}

// Postgres canonicalises INTERVAL as (months, days, microseconds).
// We only ever insert microsecond-only intervals (months = days = 0),
// but a hand-edited row or future migration could carry a `days` or
// `months` component. Days are exact (always 86_400 seconds for this
// purpose); months are not (length depends on the anchor date), so a
// non-zero `months` is surfaced as a DataIntegrity error.
fn pg_interval_to_duration(interval: PgInterval) -> Result<Duration, PersistenceError> {
    if interval.months != 0 {
        return Err(PersistenceError::DataIntegrity {
            details: format!(
                "credential_types.default_validity_duration has non-zero months: {}",
                interval.months
            ),
        });
    }
    let days_micros = i64::from(interval.days)
        .checked_mul(86_400_000_000)
        .ok_or_else(|| PersistenceError::DataIntegrity {
            details: "credential_types.default_validity_duration days component overflow".into(),
        })?;
    let total_micros = days_micros
        .checked_add(interval.microseconds)
        .ok_or_else(|| PersistenceError::DataIntegrity {
            details: "credential_types.default_validity_duration microseconds overflow".into(),
        })?;
    Ok(Duration::microseconds(total_micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_interval_to_duration_handles_microsecond_only_intervals() {
        let interval = PgInterval {
            months: 0,
            days: 0,
            microseconds: 1_500_000,
        };
        let d = pg_interval_to_duration(interval).unwrap();
        assert_eq!(d, Duration::microseconds(1_500_000));
    }

    #[test]
    fn pg_interval_to_duration_folds_days_into_microseconds() {
        let interval = PgInterval {
            months: 0,
            days: 3,
            microseconds: 0,
        };
        let d = pg_interval_to_duration(interval).unwrap();
        assert_eq!(d, Duration::days(3));
    }

    #[test]
    fn pg_interval_to_duration_rejects_non_zero_months() {
        let interval = PgInterval {
            months: 1,
            days: 0,
            microseconds: 0,
        };
        let result = pg_interval_to_duration(interval);
        assert!(matches!(
            result,
            Err(PersistenceError::DataIntegrity { .. })
        ));
    }
}
