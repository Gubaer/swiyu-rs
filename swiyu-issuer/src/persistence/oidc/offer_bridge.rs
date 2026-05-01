//! Ephemeral bridge between the management API and the OIDC binary.
//!
//! Holds the bare pre-auth code so the by-reference offer-uri fetch
//! can return it without recovering it from a hash. See
//! `specs/impl_api_oidc.md` *GET /credential-offer/{offer_id}* for
//! the lifecycle. Cross-binary use is intentional: the management
//! binary writes and deletes (on cancellation), the OIDC binary
//! reads and deletes (on issuance).

use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{CredentialOfferId, PreAuthCode};

use super::super::PersistenceError;

pub async fn insert(
    conn: &mut PgConnection,
    offer_id: &CredentialOfferId,
    pre_auth_code: &PreAuthCode,
    expires_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO oidc_offer_bridge (offer_id, pre_auth_code, expires_at)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(offer_id.bare())
    .bind(pre_auth_code.as_str())
    .bind(expires_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

/// Returns the bare pre-auth code for `offer_id` if a bridge row
/// exists, or `None` otherwise. Does not check `expires_at`: the
/// caller (the OIDC binary's offer-uri handler) is the authoritative
/// source for the observed-state rule, and chooses 404 vs 410 based
/// on the parent `credential_offers` row's expiry, not the bridge's.
pub async fn find_by_offer_id(
    conn: &mut PgConnection,
    offer_id: &CredentialOfferId,
) -> Result<Option<PreAuthCode>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT pre_auth_code
        FROM oidc_offer_bridge
        WHERE offer_id = $1
        "#,
    )
    .bind(offer_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_pre_auth_code(&row)).transpose()
}

/// Removes the bridge row for `offer_id`. Idempotent: a missing row
/// returns `Ok(())` rather than `NotFound`, because the cancel and
/// issue paths may both attempt the delete and we don't want either
/// to be a hard error if the other ran first.
pub async fn delete_for_offer(
    conn: &mut PgConnection,
    offer_id: &CredentialOfferId,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        DELETE FROM oidc_offer_bridge
        WHERE offer_id = $1
        "#,
    )
    .bind(offer_id.bare())
    .execute(conn)
    .await?;
    Ok(())
}

fn row_to_pre_auth_code(row: &PgRow) -> Result<PreAuthCode, PersistenceError> {
    let code: String = row.try_get("pre_auth_code")?;
    Ok(PreAuthCode::from_stored(code))
}

fn map_database_error(err: sqlx::Error) -> PersistenceError {
    if let Some(db_err) = err.as_database_error() {
        // Postgres SQLSTATE 23505: unique_violation.
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("unknown").to_string();
            return PersistenceError::UniqueViolation { what: constraint };
        }
    }
    PersistenceError::Db(err)
}
