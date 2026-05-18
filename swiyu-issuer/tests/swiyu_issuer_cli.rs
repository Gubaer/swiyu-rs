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

const DEV_DUMMY_VCT: &str = "urn:dummy:dummy-credential";

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_seeds_credential_type_when_tenant_has_no_issuers(pool: PgPool) {
    let engine = oauth::test_engine();
    let partner_id: Uuid = SAMPLE_PARTNER_ID.parse().unwrap();

    let tenant_id = bootstrap_dev_from_env(&pool, bootstrap_args_full(partner_id), false, &engine)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let credential_type = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
        &mut conn,
        &tenant_id,
        DEV_DUMMY_VCT,
    )
    .await
    .unwrap()
    .expect("dummy credential type was seeded");
    assert_eq!(credential_type.vct, DEV_DUMMY_VCT);

    // No issuer existed, so the assignment table stays empty.
    let assignments = swiyu_issuer::persistence::issuer_credential_types::list_by_credential_type(
        &mut conn,
        &credential_type.id,
    )
    .await
    .unwrap();
    assert!(assignments.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_assigns_credential_type_to_existing_issuer(pool: PgPool) {
    // Create the tenant first so the issuer-insert FK is satisfied.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;

    // Seed via the helper directly so the test doesn't have to thread
    // a matching partner_id through the BootstrapDevTenantArgs path.
    swiyu_issuer::cli::tenant::seed_dev_credential_type_and_assignments(&pool, &tenant_id, false)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let credential_type = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
        &mut conn,
        &tenant_id,
        DEV_DUMMY_VCT,
    )
    .await
    .unwrap()
    .expect("credential type was seeded");
    let assignments = swiyu_issuer::persistence::issuer_credential_types::list_by_credential_type(
        &mut conn,
        &credential_type.id,
    )
    .await
    .unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].issuer_id, issuer.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_is_idempotent_without_force(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    swiyu_issuer::cli::tenant::seed_dev_credential_type_and_assignments(&pool, &tenant_id, false)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let row1 = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
        &mut conn,
        &tenant_id,
        DEV_DUMMY_VCT,
    )
    .await
    .unwrap()
    .unwrap();
    drop(conn);

    // Second run without --force leaves the row untouched.
    swiyu_issuer::cli::tenant::seed_dev_credential_type_and_assignments(&pool, &tenant_id, false)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let row2 = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
        &mut conn,
        &tenant_id,
        DEV_DUMMY_VCT,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row1.id, row2.id);
    assert_eq!(row1.updated_at, row2.updated_at);
}

#[sqlx::test(migrations = "./migrations")]
async fn bootstrap_with_force_rewrites_edited_row(pool: PgPool) {
    use serde_json::json;
    use swiyu_issuer::persistence::credential_types::{StructuredUpdate, update_blob_schema};

    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    swiyu_issuer::cli::tenant::seed_dev_credential_type_and_assignments(&pool, &tenant_id, false)
        .await
        .unwrap();

    // Simulate a contributor edit: change a structured field and
    // replace the schema with something obviously different.
    let mut conn = pool.acquire().await.unwrap();
    let initial = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
        &mut conn,
        &tenant_id,
        DEV_DUMMY_VCT,
    )
    .await
    .unwrap()
    .unwrap();
    swiyu_issuer::persistence::credential_types::update_structured(
        &mut conn,
        &tenant_id,
        &initial.id,
        StructuredUpdate {
            internal_description: Some("hand-edited by contributor"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    update_blob_schema(
        &mut conn,
        &tenant_id,
        &initial.id,
        &json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": { "age": { "type": "integer" } },
            "required": ["age"]
        }),
    )
    .await
    .unwrap();
    drop(conn);

    // --force resets the row to the dummy defaults.
    swiyu_issuer::cli::tenant::seed_dev_credential_type_and_assignments(&pool, &tenant_id, true)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let rewritten = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
        &mut conn,
        &tenant_id,
        DEV_DUMMY_VCT,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rewritten.id, initial.id);
    assert_eq!(
        rewritten.internal_description.as_deref(),
        Some("Auto-seeded dummy credential type for local development"),
    );
    // The schema is back to the dummy first_name/last_name shape.
    assert_eq!(
        rewritten.claim_schema["required"],
        json!(["first_name", "last_name"])
    );
}

mod ensure_dev_issuer_tests {
    use super::*;
    use chrono::Utc;
    use std::time::Duration as StdDuration;
    use swiyu_issuer::cli::tenant::{
        EnsureDevIssuerArgs, EnsureDevIssuerError, EnsureDevIssuerOutcome,
        ensure_dev_issuer_from_env,
    };
    use swiyu_issuer::domain::{IssuerId, IssuerState};
    use swiyu_issuer::test_support::persistence::issuers::insert_test_with_did;

    async fn insert_tenant_with_partner_and_display(
        pool: &PgPool,
        partner_id: Uuid,
        display_name: Option<&str>,
    ) -> TenantId {
        let tenant_id = TenantId::generate();
        sqlx::query("INSERT INTO tenants (id, partner_id, display_name) VALUES ($1, $2, $3)")
            .bind(tenant_id.bare())
            .bind(partner_id)
            .bind(display_name)
            .execute(pool)
            .await
            .unwrap();
        tenant_id
    }

    fn quick_args(partner_id: Uuid) -> EnsureDevIssuerArgs {
        EnsureDevIssuerArgs {
            partner_id,
            poll_interval: StdDuration::from_millis(20),
            timeout: StdDuration::from_secs(2),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn returns_already_active_and_writes_assignment(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let tenant_id =
            insert_tenant_with_partner_and_display(&pool, partner_id, Some("Dev Tenant")).await;
        let issuer =
            swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id)
                .await;

        let outcome = ensure_dev_issuer_from_env(&pool, quick_args(partner_id))
            .await
            .unwrap();
        match &outcome {
            EnsureDevIssuerOutcome::AlreadyActive { issuer_id } => {
                assert_eq!(issuer_id, &issuer.id);
            }
            other => panic!("expected AlreadyActive, got {other:?}"),
        }

        let task_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM operation_tasks WHERE tenant_id = $1")
                .bind(tenant_id.bare())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            task_count.0, 0,
            "no CreateIssuer task should have been enqueued"
        );

        // The defensive re-seed wrote the credential type + assignment.
        let mut conn = pool.acquire().await.unwrap();
        let ct = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
            &mut conn,
            &tenant_id,
            "urn:dummy:dummy-credential",
        )
        .await
        .unwrap()
        .unwrap();
        let assignments =
            swiyu_issuer::persistence::issuer_credential_types::list_by_credential_type(
                &mut conn, &ct.id,
            )
            .await
            .unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].issuer_id, issuer.id);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn returns_deactivated_only_and_skips_seed(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let tenant_id = insert_tenant_with_partner_and_display(&pool, partner_id, None).await;
        let mut deactivated = swiyu_issuer::test_support::persistence::issuers::active(&tenant_id);
        deactivated.state = Some(IssuerState::Deactivated);
        swiyu_issuer::test_support::persistence::issuers::insert(&pool, &deactivated).await;

        let outcome = ensure_dev_issuer_from_env(&pool, quick_args(partner_id))
            .await
            .unwrap();
        assert!(matches!(outcome, EnsureDevIssuerOutcome::DeactivatedOnly));

        let task_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM operation_tasks WHERE tenant_id = $1")
                .bind(tenant_id.bare())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(task_count.0, 0);

        let mut conn = pool.acquire().await.unwrap();
        let ct = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
            &mut conn,
            &tenant_id,
            "urn:dummy:dummy-credential",
        )
        .await
        .unwrap();
        assert!(
            ct.is_none(),
            "deactivated-only branch must not run the credential-type seed",
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn returns_timeout_when_task_never_terminates(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let _tenant_id =
            insert_tenant_with_partner_and_display(&pool, partner_id, Some("Dev Tenant")).await;

        let args = EnsureDevIssuerArgs {
            partner_id,
            poll_interval: StdDuration::from_millis(10),
            timeout: StdDuration::from_millis(150),
        };
        let err = ensure_dev_issuer_from_env(&pool, args).await.unwrap_err();
        assert!(
            matches!(err, EnsureDevIssuerError::Timeout { .. }),
            "expected Timeout, got {err:?}",
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn returns_tenant_not_found_for_unknown_partner_id(pool: PgPool) {
        let err = ensure_dev_issuer_from_env(&pool, quick_args(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, EnsureDevIssuerError::TenantNotFound { .. }),
            "expected TenantNotFound, got {err:?}",
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn enqueued_task_derives_display_name_from_tenant(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let tenant_id =
            insert_tenant_with_partner_and_display(&pool, partner_id, Some("Karl Inc")).await;

        // Tight timeout — we don't simulate completion; we only care
        // about the task row that was inserted before the timeout
        // fired.
        let args = EnsureDevIssuerArgs {
            partner_id,
            poll_interval: StdDuration::from_millis(20),
            timeout: StdDuration::from_millis(100),
        };
        let _err = ensure_dev_issuer_from_env(&pool, args).await.unwrap_err();

        let row: (serde_json::Value,) = sqlx::query_as(
            "SELECT input FROM operation_tasks
             WHERE tenant_id = $1 AND task_type = 'create_issuer'",
        )
        .bind(tenant_id.bare())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0["display_name"], "Karl Inc - dev issuer");
        assert_eq!(row.0["description"], "");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn enqueued_task_falls_back_when_tenant_has_no_display_name(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let tenant_id = insert_tenant_with_partner_and_display(&pool, partner_id, None).await;

        let args = EnsureDevIssuerArgs {
            partner_id,
            poll_interval: StdDuration::from_millis(20),
            timeout: StdDuration::from_millis(100),
        };
        let _err = ensure_dev_issuer_from_env(&pool, args).await.unwrap_err();

        let row: (serde_json::Value,) = sqlx::query_as(
            "SELECT input FROM operation_tasks
             WHERE tenant_id = $1 AND task_type = 'create_issuer'",
        )
        .bind(tenant_id.bare())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0["display_name"], "Dev Issuer");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn returns_provisioned_when_simulated_worker_completes_task(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let tenant_id =
            insert_tenant_with_partner_and_display(&pool, partner_id, Some("Dev Tenant")).await;

        // Spawn a fake worker: wait for the task row to appear, insert
        // an Active issuer matching its result_issuer_id, then flip the
        // task to Completed. The main function's polling loop should
        // converge on Provisioned shortly after.
        let fake_pool = pool.clone();
        let fake_tenant = tenant_id.clone();
        let fake = tokio::spawn(async move {
            for _ in 0..200 {
                let row: Option<(String, String)> = sqlx::query_as(
                    "SELECT id, result_issuer_id
                     FROM operation_tasks
                     WHERE tenant_id = $1
                       AND task_type = 'create_issuer'
                       AND state = 'pending'
                     LIMIT 1",
                )
                .bind(fake_tenant.bare())
                .fetch_optional(&fake_pool)
                .await
                .unwrap();
                if let Some((task_id_bare, issuer_id_bare)) = row {
                    let issuer_id = IssuerId::from_bare(&issuer_id_bare).unwrap();
                    insert_test_with_did(&fake_pool, &fake_tenant, &issuer_id).await;
                    sqlx::query(
                        "UPDATE operation_tasks
                         SET state = 'completed',
                             completed_at = $1,
                             updated_at = $1
                         WHERE id = $2",
                    )
                    .bind(Utc::now())
                    .bind(&task_id_bare)
                    .execute(&fake_pool)
                    .await
                    .unwrap();
                    return;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
            panic!("fake worker: pending task never appeared");
        });

        let args = EnsureDevIssuerArgs {
            partner_id,
            poll_interval: StdDuration::from_millis(10),
            timeout: StdDuration::from_secs(5),
        };
        let outcome = ensure_dev_issuer_from_env(&pool, args).await.unwrap();
        let (provisioned_issuer_id, provisioned_task_id) = match outcome {
            EnsureDevIssuerOutcome::Provisioned { issuer_id, task_id } => (issuer_id, task_id),
            other => panic!("expected Provisioned, got {other:?}"),
        };
        fake.await.unwrap();

        // The fake worker stamped the result_issuer_id matching the
        // function's reported issuer_id.
        let row: (String, String) =
            sqlx::query_as("SELECT id, result_issuer_id FROM operation_tasks WHERE id = $1")
                .bind(provisioned_task_id.bare())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, provisioned_task_id.bare());
        assert_eq!(row.1, provisioned_issuer_id.bare());

        // Re-seed wrote the assignment row.
        let mut conn = pool.acquire().await.unwrap();
        let ct = swiyu_issuer::persistence::credential_types::find_by_vct_for_tenant(
            &mut conn,
            &tenant_id,
            "urn:dummy:dummy-credential",
        )
        .await
        .unwrap()
        .unwrap();
        let assignments =
            swiyu_issuer::persistence::issuer_credential_types::list_by_credential_type(
                &mut conn, &ct.id,
            )
            .await
            .unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].issuer_id, provisioned_issuer_id);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn returns_task_failed_when_simulated_worker_marks_failed(pool: PgPool) {
        let partner_id = Uuid::new_v4();
        let tenant_id = insert_tenant_with_partner_and_display(&pool, partner_id, None).await;

        let fake_pool = pool.clone();
        let fake_tenant = tenant_id.clone();
        let fake = tokio::spawn(async move {
            for _ in 0..200 {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT id FROM operation_tasks
                     WHERE tenant_id = $1
                       AND task_type = 'create_issuer'
                       AND state = 'pending'
                     LIMIT 1",
                )
                .bind(fake_tenant.bare())
                .fetch_optional(&fake_pool)
                .await
                .unwrap();
                if let Some((task_id_bare,)) = row {
                    sqlx::query(
                        "UPDATE operation_tasks
                         SET state = 'failed',
                             error_code = 'registry_unreachable',
                             error_message = 'simulated worker failure',
                             completed_at = $1,
                             updated_at = $1
                         WHERE id = $2",
                    )
                    .bind(Utc::now())
                    .bind(&task_id_bare)
                    .execute(&fake_pool)
                    .await
                    .unwrap();
                    return;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
            panic!("fake worker: pending task never appeared");
        });

        let args = EnsureDevIssuerArgs {
            partner_id,
            poll_interval: StdDuration::from_millis(10),
            timeout: StdDuration::from_secs(5),
        };
        let err = ensure_dev_issuer_from_env(&pool, args).await.unwrap_err();
        fake.await.unwrap();

        match err {
            EnsureDevIssuerError::TaskFailed {
                error_code,
                error_message,
                ..
            } => {
                assert_eq!(error_code.as_deref(), Some("registry_unreachable"));
                assert_eq!(error_message.as_deref(), Some("simulated worker failure"));
            }
            other => panic!("expected TaskFailed, got {other:?}"),
        }
    }
}
