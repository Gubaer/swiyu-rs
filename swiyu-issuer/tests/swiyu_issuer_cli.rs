//! Integration tests for `swiyu_issuer::cli::tenant`.
//!
//! Exercises the function the `swiyu-issuer-cli` binary forwards to,
//! against a freshly created Postgres database created by `sqlx::test`.

#[path = "common/mod.rs"]
mod common;

use secrecy::SecretString;
use sqlx::PgPool;
use uuid::Uuid;

use swiyu_issuer::cli::tenant::{
    CreateTenantError, ImportOauthRefreshTokenError, SeedOutcome, SetOauthCredentialsError,
    UpdateTenantError, create as create_tenant, import_oauth_refresh_token, set_oauth_credentials,
    update as update_tenant,
};
use swiyu_issuer::domain::{
    AnySecretEncryptionEngine, Ciphertext, SecretEncryptionEngine, TenantId,
};
use swiyu_issuer::persistence::tenant_secret_keys::oauth2_client_secret_key_name;
use swiyu_issuer::persistence::tenants;

use common::tenants::insert_test_tenant;

async fn read_refresh_token(
    pool: &PgPool,
    tenant_id: &TenantId,
    engine: &AnySecretEncryptionEngine,
) -> Option<String> {
    common::oauth::read_refresh_token(pool, tenant_id, engine).await
}

async fn read_client_credentials(
    pool: &PgPool,
    tenant_id: &TenantId,
    engine: &AnySecretEncryptionEngine,
) -> (Option<String>, Option<String>) {
    let row: (Option<String>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT oauth_client_id, oauth_client_secret FROM tenants WHERE id = $1")
            .bind(tenant_id.bare())
            .fetch_one(pool)
            .await
            .unwrap();
    let (client_id, blob) = row;
    let client_secret = match blob {
        None => None,
        Some(bytes) => {
            let plaintext = engine
                .decrypt(
                    &oauth2_client_secret_key_name(tenant_id),
                    &Ciphertext::from(bytes),
                )
                .await
                .unwrap();
            Some(String::from_utf8(plaintext).unwrap())
        }
    };
    (client_id, client_secret)
}

async fn write_client_credentials_directly(
    pool: &PgPool,
    tenant_id: &TenantId,
    engine: &AnySecretEncryptionEngine,
    client_id: &str,
    client_secret: &str,
) {
    let blob = engine
        .encrypt(
            &oauth2_client_secret_key_name(tenant_id),
            client_secret.as_bytes(),
        )
        .await
        .unwrap()
        .into_bytes();
    sqlx::query(
        "UPDATE tenants
         SET oauth_client_id = $1, oauth_client_secret = $2
         WHERE id = $3",
    )
    .bind(client_id)
    .bind(blob)
    .bind(tenant_id.bare())
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn import_writes_refresh_token_for_existing_tenant(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("fresh-renewal-token".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("fresh-renewal-token"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_returns_tenant_not_found_for_unknown_tenant(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();

    let err = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("ignored".to_string()),
        false,
        &engine,
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
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let first = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("first".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();
    let second = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("second".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(first, SeedOutcome::Wrote);
    assert_eq!(second, SeedOutcome::Wrote);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("second"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_skip_when_only_if_empty_and_already_set(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("original".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();

    let outcome = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("would-overwrite".to_string()),
        true,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Skipped);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("original"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn import_writes_when_only_if_empty_and_column_null(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = import_oauth_refresh_token(
        &pool,
        &tenant_id,
        SecretString::from("seed-from-null".to_string()),
        true,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("seed-from-null"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_writes_both_columns(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "client-A".to_string(),
        SecretString::from("secret-A".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_id.as_deref(), Some("client-A"));
    assert_eq!(client_secret.as_deref(), Some("secret-A"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_persists_ciphertext_not_plaintext(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    set_oauth_credentials(
        &pool,
        &tenant_id,
        "client".to_string(),
        SecretString::from("very-secret".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();

    // Raw row read: the BYTEA column must not contain the plaintext
    // anywhere — confirms the CLI/repository path encrypts before
    // writing rather than coincidentally hitting the right column.
    let raw: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT oauth_client_secret FROM tenants WHERE id = $1")
            .bind(tenant_id.bare())
            .fetch_one(&pool)
            .await
            .unwrap();
    let bytes = raw.expect("column populated");
    assert!(
        !bytes
            .windows(b"very-secret".len())
            .any(|w| w == b"very-secret"),
        "ciphertext column unexpectedly contains the plaintext",
    );

    // Round-trip: the repository read path decrypts the same value.
    let (_, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_secret.as_deref(), Some("very-secret"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_skip_when_only_if_empty_and_both_set(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    write_client_credentials_directly(&pool, &tenant_id, &engine, "original-id", "original-secret")
        .await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "would-overwrite-id".to_string(),
        SecretString::from("would-overwrite-secret".to_string()),
        true,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Skipped);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_id.as_deref(), Some("original-id"));
    assert_eq!(client_secret.as_deref(), Some("original-secret"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_writes_when_only_if_empty_and_columns_null(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "client-from-null".to_string(),
        SecretString::from("secret-from-null".to_string()),
        true,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_id.as_deref(), Some("client-from-null"));
    assert_eq!(client_secret.as_deref(), Some("secret-from-null"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_overwrites_unconditionally_without_flag(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    write_client_credentials_directly(&pool, &tenant_id, &engine, "old-id", "old-secret").await;

    let outcome = set_oauth_credentials(
        &pool,
        &tenant_id,
        "new-id".to_string(),
        SecretString::from("new-secret".to_string()),
        false,
        &engine,
    )
    .await
    .unwrap();

    assert_eq!(outcome, SeedOutcome::Wrote);
    let (client_id, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_id.as_deref(), Some("new-id"));
    assert_eq!(client_secret.as_deref(), Some("new-secret"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_oauth_credentials_returns_tenant_not_found_for_unknown_tenant(pool: PgPool) {
    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();

    let err = set_oauth_credentials(
        &pool,
        &tenant_id,
        "ignored".to_string(),
        SecretString::from("ignored".to_string()),
        false,
        &engine,
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

#[sqlx::test(migrations = "./migrations")]
async fn create_inserts_new_tenant_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef".parse().unwrap();

    create_tenant(
        &pool,
        &tenant_id,
        partner_id,
        Some("Canton".to_string()),
        Some("description".to_string()),
    )
    .await
    .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, partner_id);
    assert_eq!(tenant.display_name.as_deref(), Some("Canton"));
    assert_eq!(tenant.description.as_deref(), Some("description"));
}

#[sqlx::test(migrations = "./migrations")]
async fn create_returns_already_exists_for_colliding_tenant_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef".parse().unwrap();

    create_tenant(&pool, &tenant_id, partner_id, None, None)
        .await
        .unwrap();

    let err = create_tenant(&pool, &tenant_id, partner_id, None, None)
        .await
        .unwrap_err();
    match err {
        CreateTenantError::AlreadyExists(id) => assert_eq!(id, tenant_id.bare()),
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn update_partial_writes_only_specified_fields(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef".parse().unwrap();

    create_tenant(
        &pool,
        &tenant_id,
        partner_id,
        Some("original-name".to_string()),
        Some("original-desc".to_string()),
    )
    .await
    .unwrap();

    update_tenant(
        &pool,
        &tenant_id,
        None,
        Some("updated-name".to_string()),
        None,
    )
    .await
    .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, partner_id);
    assert_eq!(tenant.display_name.as_deref(), Some("updated-name"));
    assert_eq!(tenant.description.as_deref(), Some("original-desc"));
}

#[sqlx::test(migrations = "./migrations")]
async fn update_returns_tenant_not_found_for_unknown_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();

    let err = update_tenant(&pool, &tenant_id, None, Some("ignored".to_string()), None)
        .await
        .unwrap_err();
    match err {
        UpdateTenantError::TenantNotFound(id) => assert_eq!(id, tenant_id.bare()),
        other => panic!("expected TenantNotFound, got {other:?}"),
    }
}
