use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCodeHash, TenantId,
};

use super::PersistenceError;

pub async fn insert(
    conn: &mut PgConnection,
    offer: &CredentialOffer,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO credential_offers (
            id, tenant_id, issuer_id, vct, claims, state,
            pre_auth_code_hash, expires_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(offer.id.bare())
    .bind(offer.tenant_id.bare())
    .bind(offer.issuer_id.bare())
    .bind(&offer.vct)
    .bind(&offer.claims)
    .bind(offer.state.as_str())
    .bind(offer.pre_auth_code_hash.as_str())
    .bind(offer.expires_at)
    .bind(offer.created_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    Ok(())
}

pub async fn find_by_id(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
) -> Result<CredentialOffer, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, issuer_id, vct, claims, state,
               pre_auth_code_hash, expires_at, created_at
        FROM credential_offers
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
        "#,
    )
    .bind(offer_id.bare())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?;

    match row {
        None => Err(PersistenceError::NotFound),
        Some(row) => row_to_offer(&row),
    }
}

fn row_to_offer(row: &PgRow) -> Result<CredentialOffer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let vct: String = row.try_get("vct")?;
    let claims: Value = row.try_get("claims")?;
    let state_str: String = row.try_get("state")?;
    let pre_auth_code_hash: String = row.try_get("pre_auth_code_hash")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;

    Ok(CredentialOffer {
        id: CredentialOfferId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        issuer_id: IssuerId::from_bare(issuer_id).map_err(integrity_from)?,
        vct,
        claims,
        state: CredentialOfferState::parse(&state_str).map_err(integrity_from)?,
        pre_auth_code_hash: PreAuthCodeHash::from_stored(pre_auth_code_hash),
        expires_at,
        created_at,
    })
}

fn integrity_from(err: crate::domain::DomainError) -> PersistenceError {
    PersistenceError::DataIntegrity {
        details: err.to_string(),
    }
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
