use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use sqlx::postgres::PgConnection;
use uuid::Uuid;

use crate::domain::secret_encryption_engine::{
    AnySecretEncryptionEngine, Ciphertext, SecretEncryptionEngine,
};
use crate::domain::{Tenant, TenantId};

use super::PersistenceError;
use super::helpers::map_database_error;
use super::tenant_secret_keys::{oauth2_client_secret_key_name, oauth2_refresh_token_key_name};

pub async fn find_by_id(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
) -> Result<Option<Tenant>, PersistenceError> {
    let tenant = sqlx::query_as::<_, Tenant>(
        r#"
        SELECT id,
               partner_id,
               display_name,
               description,
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

/// At-most-one lookup by `partner_id`. The UNIQUE constraint on the
/// column guarantees the result is single-row.
pub async fn find_by_partner_id(
    conn: &mut PgConnection,
    partner_id: Uuid,
) -> Result<Option<Tenant>, PersistenceError> {
    let tenant = sqlx::query_as::<_, Tenant>(
        r#"
        SELECT id,
               partner_id,
               display_name,
               description,
               oauth_client_id,
               oauth_client_secret,
               oauth_refresh_token
        FROM tenants
        WHERE partner_id = $1
        "#,
    )
    .bind(partner_id)
    .fetch_optional(conn)
    .await?;

    Ok(tenant)
}

/// Outcome of an `update_metadata` call.
///
/// `Updated` covers every successful path including a no-op call that
/// supplies none of the optional fields — the WHERE clause still
/// confirms the row exists.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated,
    NotFound,
}

/// Inserts a new tenant row with the four operator-supplied columns.
///
/// The OAuth2 columns and API tokens are not touched here; callers
/// populate them via the dedicated subcommands. The caller controls
/// the surrounding transaction.
pub async fn insert(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    partner_id: Uuid,
    display_name: Option<&str>,
    description: Option<&str>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO tenants (id, partner_id, display_name, description)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(tenant_id)
    .bind(partner_id)
    .bind(display_name)
    .bind(description)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    Ok(())
}

/// Partially updates `partner_id`, `display_name`, and/or `description`
/// for the named tenant. A field left `None` is not touched.
///
/// Calling with all three fields `None` is valid; the call still
/// verifies the row exists and returns `Updated` accordingly. The
/// caller controls the surrounding transaction.
pub async fn update_metadata(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    partner_id: Option<Uuid>,
    display_name: Option<&str>,
    description: Option<&str>,
) -> Result<UpdateOutcome, PersistenceError> {
    // Build SET clauses dynamically so omitted fields keep their
    // current value. The match below assigns each column to its
    // existing value when the caller didn't ask to change it; this
    // is simpler than concatenating SQL fragments at runtime and
    // keeps the query plan stable.
    let result = sqlx::query(
        r#"
        UPDATE tenants
        SET partner_id   = COALESCE($2, partner_id),
            display_name = CASE WHEN $3::bool THEN $4 ELSE display_name END,
            description  = CASE WHEN $5::bool THEN $6 ELSE description  END
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .bind(partner_id)
    .bind(display_name.is_some())
    .bind(display_name)
    .bind(description.is_some())
    .bind(description)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        Ok(UpdateOutcome::NotFound)
    } else {
        Ok(UpdateOutcome::Updated)
    }
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
/// row lock and decrypts the two encrypted columns through `engine`.
///
/// Must be called from within a transaction — the lock is released
/// when the surrounding transaction commits or rolls back. Returns
/// `Ok(None)` when no row matches `tenant_id`.
pub async fn read_oauth_credentials_for_update(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    engine: &AnySecretEncryptionEngine,
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
    let client_secret_blob: Option<Vec<u8>> = row.try_get("oauth_client_secret")?;
    let refresh_token_blob: Option<Vec<u8>> = row.try_get("oauth_refresh_token")?;

    let client_secret = match client_secret_blob {
        None => None,
        Some(bytes) => Some(
            decrypt_to_secret_string(
                engine,
                &oauth2_client_secret_key_name(tenant_id),
                &Ciphertext::from(bytes),
                "oauth_client_secret",
            )
            .await?,
        ),
    };
    let refresh_token = match refresh_token_blob {
        None => None,
        Some(bytes) => Some(
            decrypt_to_secret_string(
                engine,
                &oauth2_refresh_token_key_name(tenant_id),
                &Ciphertext::from(bytes),
                "oauth_refresh_token",
            )
            .await?,
        ),
    };

    Ok(Some(TenantOauthCreds {
        client_id,
        client_secret,
        refresh_token,
    }))
}

/// Writes a new value for `oauth_refresh_token`, encrypting it under
/// the tenant's `oauth2_refresh_token` key.
///
/// The caller controls the surrounding transaction; this helper does
/// not commit. Pairs with [`read_oauth_credentials_for_update`] to
/// implement the rotation step of an OAuth2 refresh-token grant.
pub async fn write_oauth_refresh_token(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    refresh_token: &SecretString,
    engine: &AnySecretEncryptionEngine,
) -> Result<(), PersistenceError> {
    let key_name = oauth2_refresh_token_key_name(tenant_id);
    let ciphertext = engine
        .encrypt(&key_name, refresh_token.expose_secret().as_bytes())
        .await?;

    let result = sqlx::query(
        r#"
        UPDATE tenants
        SET oauth_refresh_token = $1
        WHERE id = $2
        "#,
    )
    .bind(ciphertext.as_bytes())
    .bind(tenant_id)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Writes new values for `oauth_client_id` and `oauth_client_secret`
/// in a single statement; the secret is encrypted under the tenant's
/// `oauth2_client_secret` key.
///
/// The caller controls the surrounding transaction; this helper does
/// not commit. The two columns are always written together — partial
/// updates would leave the row in a state the
/// [`OAuth2TokenProvider`][crate::domain::oauth2::OAuth2TokenProvider]
/// rejects with
/// [`MissingCredentials`][crate::domain::oauth2::TokenProviderError::MissingCredentials].
pub async fn write_oauth_client_credentials(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    client_id: &str,
    client_secret: &SecretString,
    engine: &AnySecretEncryptionEngine,
) -> Result<(), PersistenceError> {
    let key_name = oauth2_client_secret_key_name(tenant_id);
    let ciphertext = engine
        .encrypt(&key_name, client_secret.expose_secret().as_bytes())
        .await?;

    let result = sqlx::query(
        r#"
        UPDATE tenants
        SET oauth_client_id     = $1,
            oauth_client_secret = $2
        WHERE id = $3
        "#,
    )
    .bind(client_id)
    .bind(ciphertext.as_bytes())
    .bind(tenant_id)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

async fn decrypt_to_secret_string(
    engine: &AnySecretEncryptionEngine,
    key_name: &str,
    ciphertext: &Ciphertext,
    column: &str,
) -> Result<SecretString, PersistenceError> {
    let plaintext = engine.decrypt(key_name, ciphertext).await?;
    let s = String::from_utf8(plaintext).map_err(|err| PersistenceError::DataIntegrity {
        details: format!("{column}: decrypted bytes are not valid UTF-8: {err}"),
    })?;
    Ok(SecretString::from(s))
}
