use secrecy::SecretString;
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{Tenant, TenantId};

use super::PersistenceError;
use super::helpers::integrity_from;

pub async fn find_by_id(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
) -> Result<Option<Tenant>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id,
               partner_id,
               oauth_client_id,
               oauth_client_secret,
               oauth_refresh_token
        FROM tenants
        WHERE id = $1
        "#,
    )
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_tenant(&row)).transpose()
}

fn row_to_tenant(row: &PgRow) -> Result<Tenant, PersistenceError> {
    let id: String = row.try_get("id")?;
    let partner_id: Option<String> = row.try_get("partner_id")?;
    let oauth_client_id: Option<String> = row.try_get("oauth_client_id")?;
    let oauth_client_secret: Option<String> = row.try_get("oauth_client_secret")?;
    let oauth_refresh_token: Option<String> = row.try_get("oauth_refresh_token")?;
    Ok(Tenant {
        id: TenantId::from_bare(id).map_err(integrity_from)?,
        partner_id,
        oauth_client_id,
        oauth_client_secret: oauth_client_secret.map(SecretString::from),
        oauth_refresh_token: oauth_refresh_token.map(SecretString::from),
    })
}
