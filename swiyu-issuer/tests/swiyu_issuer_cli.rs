//! Integration tests for `swiyu_issuer::cli::tenant`.
//!
//! Exercises the function the `swiyu-issuer-cli` binary forwards to,
//! against a freshly created Postgres database created by `sqlx::test`.

use secrecy::SecretString;
use sqlx::PgPool;
use swiyu_issuer::test_support::fixtures::SAMPLE_PARTNER_ID;
use swiyu_issuer::test_support::oauth;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;
use uuid::Uuid;

use swiyu_issuer::cli::tenant::{
    BootstrapDevTenantArgs, CreateTenantError, DevTenantEnvError, ImportOauthRefreshTokenError,
    SeedOutcome, SetOauthCredentialsError, UpdateTenantError, bootstrap_dev_from_env,
    create as create_tenant, import_oauth_refresh_token, parse_dev_tenant_args,
    set_oauth_credentials, update as update_tenant,
};
use swiyu_issuer::domain::{
    AnySecretEncryptionEngine, Ciphertext, SecretEncryptionEngine, TenantId,
};
use swiyu_issuer::persistence::tenant_secret_keys::oauth2_client_secret_key_name;
use swiyu_issuer::persistence::tenants;

use oauth::read_refresh_token;

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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let engine = oauth::test_engine();
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
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

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
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

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
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

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

fn bootstrap_args_full(partner_id: Uuid) -> BootstrapDevTenantArgs {
    BootstrapDevTenantArgs {
        partner_id,
        display_name: Some("Dev Canton".to_string()),
        description: Some("contributor dev tenant".to_string()),
        client_id: Some("client-from-env".to_string()),
        client_secret: Some(SecretString::from("secret-from-env".to_string())),
        refresh_token: Some(SecretString::from("refresh-from-env".to_string())),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_dev_from_env_creates_missing_tenant(pool: PgPool) {
    let engine = oauth::test_engine();
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

    let tenant_id = bootstrap_dev_from_env(&pool, bootstrap_args_full(partner_id), false, &engine)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, partner_id);
    assert_eq!(tenant.display_name.as_deref(), Some("Dev Canton"));
    assert_eq!(
        tenant.description.as_deref(),
        Some("contributor dev tenant"),
    );
    assert_eq!(tenant.oauth_client_id.as_deref(), Some("client-from-env"));
    let (_, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_secret.as_deref(), Some("secret-from-env"));
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("refresh-from-env"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_dev_from_env_without_force_preserves_existing_oauth(pool: PgPool) {
    let engine = oauth::test_engine();
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

    // First call: missing -> create with one set of oauth values.
    let original_args = BootstrapDevTenantArgs {
        partner_id,
        display_name: Some("Original".to_string()),
        description: Some("first".to_string()),
        client_id: Some("original-client".to_string()),
        client_secret: Some(SecretString::from("original-secret".to_string())),
        refresh_token: Some(SecretString::from("original-refresh".to_string())),
    };
    let tenant_id = bootstrap_dev_from_env(&pool, original_args, false, &engine)
        .await
        .unwrap();

    // Second call without --force: env carries new values but the
    // oauth columns are non-NULL, so they survive untouched; metadata
    // is also untouched.
    let new_args = BootstrapDevTenantArgs {
        partner_id,
        display_name: Some("Renamed".to_string()),
        description: Some("second".to_string()),
        client_id: Some("new-client".to_string()),
        client_secret: Some(SecretString::from("new-secret".to_string())),
        refresh_token: Some(SecretString::from("new-refresh".to_string())),
    };
    let second_id = bootstrap_dev_from_env(&pool, new_args, false, &engine)
        .await
        .unwrap();
    assert_eq!(second_id, tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.display_name.as_deref(), Some("Original"));
    assert_eq!(tenant.description.as_deref(), Some("first"));
    assert_eq!(tenant.oauth_client_id.as_deref(), Some("original-client"));
    let (_, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_secret.as_deref(), Some("original-secret"));
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("original-refresh"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_dev_from_env_with_force_syncs_row_from_env(pool: PgPool) {
    let engine = oauth::test_engine();
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

    bootstrap_dev_from_env(
        &pool,
        BootstrapDevTenantArgs {
            partner_id,
            display_name: Some("Original".to_string()),
            description: Some("first".to_string()),
            client_id: Some("original-client".to_string()),
            client_secret: Some(SecretString::from("original-secret".to_string())),
            refresh_token: Some(SecretString::from("original-refresh".to_string())),
        },
        false,
        &engine,
    )
    .await
    .unwrap();

    let tenant_id = bootstrap_dev_from_env(
        &pool,
        BootstrapDevTenantArgs {
            partner_id,
            display_name: Some("Renamed".to_string()),
            description: Some("second".to_string()),
            client_id: Some("new-client".to_string()),
            client_secret: Some(SecretString::from("new-secret".to_string())),
            refresh_token: Some(SecretString::from("new-refresh".to_string())),
        },
        true,
        &engine,
    )
    .await
    .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.display_name.as_deref(), Some("Renamed"));
    assert_eq!(tenant.description.as_deref(), Some("second"));
    assert_eq!(tenant.oauth_client_id.as_deref(), Some("new-client"));
    let (_, client_secret) = read_client_credentials(&pool, &tenant_id, &engine).await;
    assert_eq!(client_secret.as_deref(), Some("new-secret"));
    assert_eq!(
        read_refresh_token(&pool, &tenant_id, &engine)
            .await
            .as_deref(),
        Some("new-refresh"),
    );
}

#[test]
fn parse_dev_tenant_args_happy_path() {
    let env: std::collections::HashMap<&str, &str> = [
        ("DEV_TENANT_PARTNER_ID", SAMPLE_PARTNER_ID),
        ("DEV_TENANT_DISPLAY_NAME", "Dev"),
        ("DEV_TENANT_DESCRIPTION", "notes"),
        ("DEV_TENANT_CLIENT_ID", "cid"),
        ("DEV_TENANT_CLIENT_SECRET", "csec"),
        ("DEV_TENANT_REFRESH_TOKEN", "rtok"),
    ]
    .into_iter()
    .collect();
    let args = parse_dev_tenant_args(|k| env.get(k).map(|s| (*s).to_string())).unwrap();
    let expected_partner: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();
    assert_eq!(args.partner_id, expected_partner);
    assert_eq!(args.display_name.as_deref(), Some("Dev"));
    assert_eq!(args.description.as_deref(), Some("notes"));
    assert_eq!(args.client_id.as_deref(), Some("cid"));
}

#[test]
fn parse_dev_tenant_args_treats_empty_as_absent() {
    let env: std::collections::HashMap<&str, &str> = [
        ("DEV_TENANT_PARTNER_ID", SAMPLE_PARTNER_ID),
        ("DEV_TENANT_DISPLAY_NAME", ""),
        ("DEV_TENANT_CLIENT_ID", ""),
    ]
    .into_iter()
    .collect();
    let args = parse_dev_tenant_args(|k| env.get(k).map(|s| (*s).to_string())).unwrap();
    assert!(args.display_name.is_none());
    assert!(args.client_id.is_none());
}

#[test]
fn parse_dev_tenant_args_missing_partner_id_errors() {
    let err = parse_dev_tenant_args(|_| None).unwrap_err();
    match err {
        DevTenantEnvError::Missing(name) => assert_eq!(name, "DEV_TENANT_PARTNER_ID"),
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[test]
fn parse_dev_tenant_args_invalid_partner_id_errors() {
    let env: std::collections::HashMap<&str, &str> = [("DEV_TENANT_PARTNER_ID", "not-a-uuid")]
        .into_iter()
        .collect();
    let err = parse_dev_tenant_args(|k| env.get(k).map(|s| (*s).to_string())).unwrap_err();
    match err {
        DevTenantEnvError::InvalidUuid(name, _) => assert_eq!(name, "DEV_TENANT_PARTNER_ID"),
        other => panic!("expected InvalidUuid, got {other:?}"),
    }
}
