//! Integration tests for `swiyu_issuer::cli::tenant`.
//!
//! Exercises the function the `swiyu-issuer-cli` binary forwards to,
//! against a freshly created Postgres database created by `sqlx::test`.

use secrecy::SecretString;
use sqlx::PgPool;

use swiyu_issuer::cli::tenant::{
    ImportOauthRefreshTokenError, SeedOutcome, SetOauthCredentialsError,
    import_oauth_refresh_token, set_oauth_credentials,
};
use swiyu_issuer::domain::TenantId;

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

async fn read_refresh_token(pool: &PgPool, tenant_id: &TenantId) -> Option<String> {
    sqlx::query_scalar("SELECT oauth_refresh_token FROM tenants WHERE id = $1")
        .bind(tenant_id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn read_client_credentials(
    pool: &PgPool,
    tenant_id: &TenantId,
) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT oauth_client_id, oauth_client_secret FROM tenants WHERE id = $1")
        .bind(tenant_id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn write_client_credentials_directly(
    pool: &PgPool,
    tenant_id: &TenantId,
    client_id: &str,
    client_secret: &str,
) {
    sqlx::query(
        "UPDATE tenants
         SET oauth_client_id = $1, oauth_client_secret = $2
         WHERE id = $3",
    )
    .bind(client_id)
    .bind(client_secret)
    .bind(tenant_id.bare())
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn import_writes_refresh_token_for_existing_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("fresh-renewal-token".to_string()),
        false,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id).await.as_deref(),
        Some("fresh-renewal-token"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_returns_tenant_not_found_for_unknown_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();

    let err = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("ignored".to_string()),
        false,
    )
    .await
    .unwrap_err();

    match err {
        ImportOauthRefreshTokenError::TenantNotFound(id) => {
            assert_eq!(id, tenant_id.bare());
        }
        other => panic!("expected TenantNotFound, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn import_overwrites_previous_refresh_token(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let first = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("first".to_string()),
        false,
    )
    .await
    .unwrap();
    let second = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("second".to_string()),
        false,
    )
    .await
    .unwrap();

    assert_eq!(first, SeedOutcome::Wrote);
    assert_eq!(second, SeedOutcome::Wrote);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id).await.as_deref(),
        Some("second"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_skip_when_only_if_empty_and_already_set(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("original".to_string()),
        false,
    )
    .await
    .unwrap();

    let outcome = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("would-overwrite".to_string()),
        true,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Skipped);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id).await.as_deref(),
        Some("original"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_writes_when_only_if_empty_and_column_null(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("seed-from-null".to_string()),
        true,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id).await.as_deref(),
        Some("seed-from-null"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_writes_both_columns(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "client-A".to_string(),
        SecretString::from("secret-A".to_string()),
        false,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id).await;
    assert_eq!(client_id.as_deref(), Some("client-A"));
    assert_eq!(client_secret.as_deref(), Some("secret-A"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_skip_when_only_if_empty_and_both_set(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    write_client_credentials_directly(&pool, &tenant_id, "original-id", "original-secret").await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "would-overwrite-id".to_string(),
        SecretString::from("would-overwrite-secret".to_string()),
        true,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Skipped);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id).await;
    assert_eq!(client_id.as_deref(), Some("original-id"));
    assert_eq!(client_secret.as_deref(), Some("original-secret"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_writes_when_only_if_empty_and_columns_null(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "client-from-null".to_string(),
        SecretString::from("secret-from-null".to_string()),
        true,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id).await;
    assert_eq!(client_id.as_deref(), Some("client-from-null"));
    assert_eq!(client_secret.as_deref(), Some("secret-from-null"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_overwrites_unconditionally_without_flag(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    write_client_credentials_directly(&pool, &tenant_id, "old-id", "old-secret").await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "new-id".to_string(),
        SecretString::from("new-secret".to_string()),
        false,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id).await;
    assert_eq!(client_id.as_deref(), Some("new-id"));
    assert_eq!(client_secret.as_deref(), Some("new-secret"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_returns_tenant_not_found_for_unknown_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();

    let err = set_oauth_credentials(
        &pool,
        &tenant_id,
        "ignored".to_string(),
        SecretString::from("ignored".to_string()),
        false,
    )
    .await
    .unwrap_err();

    match err {
        SetOauthCredentialsError::TenantNotFound(id) => {
            assert_eq!(id, tenant_id.bare());
        }
        other => panic!("expected TenantNotFound, got {other:?}"),
    }
}
