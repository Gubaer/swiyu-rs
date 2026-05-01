use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{Issuer, IssuerId, TenantId};

use super::PersistenceError;
use super::helpers::integrity_from;

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
        SELECT id, tenant_id, did, signing_key_id,
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

fn row_to_issuer(row: &PgRow) -> Result<Issuer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let did: String = row.try_get("did")?;
    let signing_key_id: String = row.try_get("signing_key_id")?;
    let display_name: Option<String> = row.try_get("display_name")?;
    let logo_uri: Option<String> = row.try_get("logo_uri")?;
    let locale: Option<String> = row.try_get("locale")?;

    Ok(Issuer {
        id: IssuerId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        did,
        signing_key_id,
        display_name,
        logo_uri,
        locale,
    })
}
