//! Integration tests for `swiyu_issuer::cli::tenant`.
//!
//! Exercises the function the `swiyu-issuer-cli` binary forwards to,
//! against a freshly created Postgres database created by `sqlx::test`.

use secrecy::SecretString;
use sqlx::PgPool;

use swiyu_issuer::cli::tenant::{ImportOauthRefreshTokenError, import_oauth_refresh_token};
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

#[sqlx::test(migrations = "./migrations")]
async fn import_writes_refresh_token_for_existing_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("fresh-renewal-token".to_string()),
    )
    .await
    .unwrap();

    assert_eq!(
        read_refresh_token(&pool, &tenant_id).await.as_deref(),
        Some("fresh-renewal-token"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_returns_tenant_not_found_for_unknown_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();

    let err =
        import_oauth_refresh_token(&pool, &tenant_id, SecretString::from("ignored".to_string()))
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

    import_oauth_refresh_token(&pool, &tenant_id, SecretString::from("first".to_string()))
        .await
        .unwrap();
    import_oauth_refresh_token(&pool, &tenant_id, SecretString::from("second".to_string()))
        .await
        .unwrap();

    assert_eq!(
        read_refresh_token(&pool, &tenant_id).await.as_deref(),
        Some("second"),
    );
}
