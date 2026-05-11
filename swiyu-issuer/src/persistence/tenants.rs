use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use sqlx::postgres::PgConnection;

use crate::domain::{Tenant, TenantId};

use super::PersistenceError;

pub async fn find_by_id(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
) -> Result<Option<Tenant>, PersistenceError> {
    let tenant = sqlx::query_as::<_, Tenant>(
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
    .bind(tenant_id)
    .fetch_optional(conn)
    .await?;

    Ok(tenant)
}

/// OAuth2 credentials read from one tenant row.
///
/// Validation of which missing-value combinations are tolerable
/// lives in the caller ([`OAuth2TokenProvider`][crate::domain::oauth2::OAuth2TokenProvider]),
/// not here.
pub struct TenantOauthCreds {
    /// NULL for tenants that do not call SWIYU registries.
    pub client_id: Option<String>,
    pub client_secret: Option<SecretString>,
    /// Rotated on every successful grant.
    pub refresh_token: Option<SecretString>,
}

/// Reads the three OAuth2 credential columns under a `FOR UPDATE`
/// row lock.
///
/// Must be called from within a transaction — the lock is released
/// when the surrounding transaction commits or rolls back. Returns
/// `Ok(None)` when no row matches `tenant_id`.
pub async fn read_oauth_credentials_for_update(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
) -> Result<Option<TenantOauthCreds>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT oauth_client_id,
               oauth_client_secret,
               oauth_refresh_token
        FROM tenants
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let client_id: Option<String> = row.try_get("oauth_client_id")?;
    let client_secret: Option<String> = row.try_get("oauth_client_secret")?;
    let refresh_token: Option<String> = row.try_get("oauth_refresh_token")?;
    Ok(Some(TenantOauthCreds {
        client_id,
        client_secret: client_secret.map(SecretString::from),
        refresh_token: refresh_token.map(SecretString::from),
    }))
}

/// Writes a new value for `oauth_refresh_token`.
///
/// The caller controls the surrounding transaction; this helper does
/// not commit. Pairs with [`read_oauth_credentials_for_update`] to
/// implement the rotation step of an OAuth2 refresh-token grant.
pub async fn write_oauth_refresh_token(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    refresh_token: &SecretString,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE tenants
        SET oauth_refresh_token = $1
        WHERE id = $2
        "#,
    )
    .bind(refresh_token.expose_secret())
    .bind(tenant_id)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Writes new values for `oauth_client_id` and `oauth_client_secret`
/// in a single statement.
///
/// The caller controls the surrounding transaction; this helper does
/// not commit. The two columns are always written together — partial
/// updates would leave the row in a state
/// [`OAuth2TokenProvider`][crate::domain::oauth2::OAuth2TokenProvider]
/// rejects with [`MissingCredentials`][crate::domain::oauth2::TokenProviderError::MissingCredentials].
pub async fn write_oauth_client_credentials(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    client_id: &str,
    client_secret: &SecretString,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE tenants
        SET oauth_client_id     = $1,
            oauth_client_secret = $2
        WHERE id = $3
        "#,
    )
    .bind(client_id)
    .bind(client_secret.expose_secret())
    .bind(tenant_id)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}
