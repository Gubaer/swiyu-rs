use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};
use uuid::Uuid;

use crate::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};

use super::PersistenceError;
use super::helpers::{integrity_from, map_database_error};

pub async fn exists_for_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<bool, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT 1 AS one
        FROM issuers
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    Ok(row.is_some())
}

/// Loads an issuer by id without scoping to a tenant.
///
/// The wallet-facing OIDC binary has no tenant in its URL, so the
/// lookup needs to fall back on the issuer id alone. The row's
/// `tenant_id` column carries the resolution, which the handler
/// then threads into any tenant-scoped persistence call (defense in
/// depth, per `aspect-multi-tenancy.md`).
///
/// Returns `Ok(None)` for "no such issuer". Callers in the OIDC
/// binary should respond with the same generic 404 they would for
/// any other unknown wallet-visible identifier.
pub async fn find_by_id(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
) -> Result<Option<Issuer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, did,
               state, description,
               authorized_key_id, authentication_key_id, assertion_key_id,
               signing_key_id,
               display_name, logo_uri, locale
        FROM issuers
        WHERE id = $1
        "#,
    )
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_issuer(&row)).transpose()
}

/// Tenant-scoped variant of [`find_by_id`].
///
/// The management API never resolves an issuer outside the caller's
/// tenant, so the SELECT filters on both columns and "wrong tenant"
/// collapses to the same `Ok(None)` as "no such issuer". Handlers
/// then map either case to a generic 404 — the BA cannot probe for
/// the existence of issuers in other tenants.
pub async fn find_by_id_for_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<Option<Issuer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, did,
               state, description,
               authorized_key_id, authentication_key_id, assertion_key_id,
               signing_key_id,
               display_name, logo_uri, locale
        FROM issuers
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_issuer(&row)).transpose()
}

pub async fn insert(conn: &mut PgConnection, issuer: &Issuer) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO issuers (
            id, tenant_id, did,
            state, description,
            authorized_key_id, authentication_key_id, assertion_key_id,
            signing_key_id,
            display_name, logo_uri, locale
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(issuer.id.bare())
    .bind(issuer.tenant_id.bare())
    .bind(&issuer.did)
    .bind(issuer.state.map(IssuerState::as_str))
    .bind(issuer.description.as_deref())
    .bind(issuer.authorized_key_id.map(|k| *k.as_uuid()))
    .bind(issuer.authentication_key_id.map(|k| *k.as_uuid()))
    .bind(issuer.assertion_key_id.map(|k| *k.as_uuid()))
    .bind(issuer.signing_key_id.as_deref())
    .bind(issuer.display_name.as_deref())
    .bind(issuer.logo_uri.as_deref())
    .bind(issuer.locale.as_deref())
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

fn row_to_issuer(row: &PgRow) -> Result<Issuer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let did: String = row.try_get("did")?;
    let state: Option<String> = row.try_get("state")?;
    let description: Option<String> = row.try_get("description")?;
    let authorized_key_id: Option<Uuid> = row.try_get("authorized_key_id")?;
    let authentication_key_id: Option<Uuid> = row.try_get("authentication_key_id")?;
    let assertion_key_id: Option<Uuid> = row.try_get("assertion_key_id")?;
    let signing_key_id: Option<String> = row.try_get("signing_key_id")?;
    let display_name: Option<String> = row.try_get("display_name")?;
    let logo_uri: Option<String> = row.try_get("logo_uri")?;
    let locale: Option<String> = row.try_get("locale")?;

    Ok(Issuer {
        id: IssuerId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        did,
        state: state
            .map(|s| IssuerState::parse(&s))
            .transpose()
            .map_err(integrity_from)?,
        description,
        authorized_key_id: authorized_key_id.map(KeyPairId::from_uuid),
        authentication_key_id: authentication_key_id.map(KeyPairId::from_uuid),
        assertion_key_id: assertion_key_id.map(KeyPairId::from_uuid),
        signing_key_id,
        display_name,
        logo_uri,
        locale,
    })
}
