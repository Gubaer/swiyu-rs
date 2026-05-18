use std::env;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use swiyu_core::did::DID;
use swiyu_core::diddoc::{DIDDoc, PublicKey};
use swiyu_core::didlog::{DIDDocState, DIDLog};
use swiyu_core::jws::VerifyingKey;
use swiyu_issuer::domain::{ApiToken, ApiTokenSecret};
use swiyu_issuer::persistence;
use thiserror::Error;
use tokio::time::sleep;
use uuid::Uuid;

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_POLL_MS: u64 = 1000;

const SMOKE_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

// vct the dev-bootstrap-issuer compose service seeds against the dev
// tenant. The smoke discovers the credential type by this vct so the
// id (which is generated per-deployment) does not need to be threaded
// through the smoke's environment.
const DUMMY_VCT: &str = "urn:dummy:dummy-credential";

const PRE_AUTHORIZED_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!("config error: {err}");
            return ExitCode::from(2);
        }
    };

    let signing_engine = env::var("SIGNING_ENGINE").unwrap_or_else(|_| "<unset>".into());
    tracing::info!(
        mgmt_url = %cfg.mgmt_url,
        oidc_url = %cfg.oidc_url,
        signing_engine = %signing_engine,
        timeout_secs = cfg.task_timeout.as_secs(),
        poll_ms = cfg.poll_interval.as_millis() as u64,
        "credential-lifecycle-smoke starting",
    );

    match run(&cfg).await {
        Ok(()) => {
            tracing::info!("=== smoke run PASSED ===");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!("=== smoke run FAILED ===");
            tracing::error!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

struct Config {
    /// Management API base, e.g. `http://localhost:8080`. Also the
    /// public-facing URL the OIDC binary advertises in its metadata,
    /// so the wallet proof's `aud` is built from this value.
    mgmt_url: String,
    /// URL the OIDC binary actually listens on, e.g.
    /// `http://localhost:8081`. In production this collapses to the
    /// same host as `mgmt_url` behind a reverse proxy; in dev they
    /// differ because compose maps each binary to its own host port.
    oidc_url: String,
    database_url: String,
    task_timeout: Duration,
    poll_interval: Duration,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let mgmt_url = required("ISSUER_BASE_URL")?
            .trim_end_matches('/')
            .to_string();
        let oidc_url = env::var("ISSUER_OIDC_HTTP_URL")
            .unwrap_or_else(|_| "http://localhost:8081".to_string())
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            mgmt_url,
            oidc_url,
            database_url: required("DATABASE_URL")?,
            task_timeout: Duration::from_secs(parse_u64_env(
                "LIFECYCLE_TIMEOUT_SECS",
                DEFAULT_TIMEOUT_SECS,
            )?),
            poll_interval: Duration::from_millis(parse_u64_env(
                "LIFECYCLE_POLL_MS",
                DEFAULT_POLL_MS,
            )?),
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be set"))
}

fn parse_u64_env(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(s) => s
            .parse::<u64>()
            .map_err(|err| format!("{name} is not a u64: {err}")),
        Err(_) => Ok(default),
    }
}

#[derive(Debug, Error)]
enum SmokeError {
    #[error("phase {phase} failed: {source}")]
    Phase {
        phase: &'static str,
        #[source]
        source: PhaseError,
    },
}

#[derive(Debug, Error)]
enum PhaseError {
    #[error("HTTP {0}: {1}")]
    Http(StatusCode, String),
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("task {task_id} failed: {code} — {message}")]
    TaskFailed {
        task_id: String,
        code: String,
        message: String,
    },
    #[error("task {task_id} did not complete within {timeout:?} (last state={last_state})")]
    TaskTimeout {
        task_id: String,
        timeout: Duration,
        last_state: String,
    },
    #[error("assertion: {0}")]
    Assertion(String),
    #[error("setup: {0}")]
    Setup(String),
    #[error("crypto: {0}")]
    Crypto(String),
}

fn assertion(msg: impl Into<String>) -> PhaseError {
    PhaseError::Assertion(msg.into())
}

fn phase(name: &'static str) -> impl FnOnce(PhaseError) -> SmokeError {
    move |source| SmokeError::Phase {
        phase: name,
        source,
    }
}

fn log_phase(n: u8, name: &str) {
    tracing::info!("=== Phase {n}/7: {name} ===");
}

#[derive(Debug, Deserialize)]
struct CreateIssuerResponse {
    task_id: String,
    issuer_id: String,
}

#[derive(Debug, Deserialize)]
struct IssuerView {
    id: String,
    did: String,
    state: String,
    description: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct TaskStatus {
    id: String,
    task_type: String,
    state: String,
    step: Option<String>,
    attempts: u32,
    next_attempt_at: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateOfferResponse {
    id: String,
    pre_auth_code: String,
    offer_deeplink: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct CredentialTypeView {
    credential_type_id: String,
    vct: String,
}

#[derive(Debug, Deserialize)]
struct ListCredentialTypesView {
    items: Vec<CredentialTypeView>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    c_nonce: String,
    c_nonce_expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct CredentialResponse {
    credential: String,
}

async fn run(cfg: &Config) -> Result<(), SmokeError> {
    let token = mint_smoke_token(&cfg.database_url)
        .await
        .map_err(phase("init"))?;
    let mgmt = Mgmt::new(&cfg.mgmt_url, &token).map_err(|e| SmokeError::Phase {
        phase: "init",
        source: PhaseError::Transport(e),
    })?;
    let oidc = Oidc::new(&cfg.oidc_url).map_err(|e| SmokeError::Phase {
        phase: "init",
        source: PhaseError::Transport(e),
    })?;

    // ---- Phase 1: create issuer ----
    log_phase(1, "create_issuer");
    let display_name = format!(
        "credential-lifecycle-smoke {}",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    );
    let create = mgmt
        .create_issuer(&display_name)
        .await
        .map_err(phase("create.submit"))?;
    tracing::info!(
        task_id = %create.task_id,
        issuer_id = %create.issuer_id,
        "create-issuer task submitted",
    );
    wait_until_completed(&mgmt, &create.task_id, cfg)
        .await
        .map_err(phase("create.poll"))?;
    let issuer = mgmt
        .get_issuer(&create.issuer_id)
        .await
        .map_err(phase("create.fetch"))?;
    log_issuer(&issuer);
    if issuer.state != "active" {
        return Err(SmokeError::Phase {
            phase: "create.assert",
            source: assertion(format!(
                "expected issuer state=active after create, got {}",
                issuer.state
            )),
        });
    }

    // ---- Phase 2: discover the dev-seeded dummy credential type
    // and assign it to the fresh issuer ----
    //
    // The dev tenant's dummy credential type is seeded by the
    // bootstrap-dev-tenant compose service; this smoke creates its
    // own fresh issuer in phase 1, so it must assign the existing
    // type before any offer-create call can succeed.
    log_phase(2, "assign_credential_type");
    let dummy = mgmt
        .find_credential_type_by_vct(DUMMY_VCT)
        .await
        .map_err(phase("assign.discover"))?;
    tracing::info!(
        credential_type_id = %dummy.credential_type_id,
        vct = %dummy.vct,
        "✓ found dev-seeded dummy credential type",
    );
    mgmt.assign_credential_type(&create.issuer_id, &dummy.credential_type_id)
        .await
        .map_err(phase("assign.post"))?;
    tracing::info!(
        issuer_id = %create.issuer_id,
        credential_type_id = %dummy.credential_type_id,
        "✓ credential type assigned to fresh issuer",
    );

    // ---- Phase 3: create credential offer ----
    log_phase(3, "create_offer");
    let offer = mgmt
        .create_offer(
            &create.issuer_id,
            &dummy.credential_type_id,
            fixture_claims(),
        )
        .await
        .map_err(phase("offer.submit"))?;
    tracing::info!(
        offer_id = %offer.id,
        deeplink = %offer.offer_deeplink,
        expires_at = %offer.expires_at,
        "credential offer created",
    );

    // ---- Phase 4: wallet — fetch offer details via OIDC ----
    log_phase(4, "wallet_fetch_offer");
    let offer_body = oidc
        .get_credential_offer(&create.issuer_id, &offer.id)
        .await
        .map_err(phase("wallet.offer.fetch"))?;
    let oidc_pre_auth_code = extract_pre_auth_code(&offer_body).map_err(|m| SmokeError::Phase {
        phase: "wallet.offer.extract",
        source: assertion(m),
    })?;
    if oidc_pre_auth_code != offer.pre_auth_code {
        return Err(SmokeError::Phase {
            phase: "wallet.offer.assert",
            source: assertion("OIDC offer's pre-auth code does not match the management response"),
        });
    }
    tracing::info!("✓ OIDC offer body matches the management API's pre-auth code");

    // ---- Phase 5: wallet — mint access token ----
    log_phase(5, "wallet_mint_token");
    let token_resp = oidc
        .mint_token(&create.issuer_id, &oidc_pre_auth_code)
        .await
        .map_err(phase("wallet.token"))?;
    if token_resp.token_type != "Bearer" {
        return Err(SmokeError::Phase {
            phase: "wallet.token.assert",
            source: assertion(format!(
                "expected token_type=Bearer, got {:?}",
                token_resp.token_type
            )),
        });
    }
    tracing::info!(
        expires_in = token_resp.expires_in,
        c_nonce_expires_in = token_resp.c_nonce_expires_in,
        "✓ access token minted",
    );

    // ---- Phase 6: wallet — fetch credential ----
    log_phase(6, "wallet_fetch_credential");
    let wallet_signing_key = SigningKey::generate(&mut OsRng);
    let proof_jwt = build_wallet_proof(
        &wallet_signing_key,
        &cfg.mgmt_url,
        &create.issuer_id,
        &token_resp.c_nonce,
    )
    .map_err(phase("wallet.proof.build"))?;
    let credential = oidc
        .fetch_credential(
            &create.issuer_id,
            &token_resp.access_token,
            &dummy.vct,
            &proof_jwt,
        )
        .await
        .map_err(phase("wallet.credential"))?;
    tracing::info!(bytes = credential.len(), "✓ credential issued");

    // ---- Phase 7: verify the JWS against the published assertion key ----
    log_phase(7, "verify_jws");
    let didlog_text = fetch_didlog(&issuer.did)
        .await
        .map_err(phase("verify.didlog.fetch"))?;
    let didlog = DIDLog::try_from_jsonl(&didlog_text).map_err(|e| SmokeError::Phase {
        phase: "verify.didlog.parse",
        source: PhaseError::Crypto(format!("parse log: {e}")),
    })?;
    let assertion_pk =
        extract_assertion_key(&didlog, &issuer.did).map_err(|m| SmokeError::Phase {
            phase: "verify.key.extract",
            source: PhaseError::Crypto(m),
        })?;
    verify_jws(&credential, &assertion_pk).map_err(phase("verify.jws"))?;
    tracing::info!("✓ credential JWS verifies against the published assertion key");

    Ok(())
}

fn fixture_claims() -> Value {
    // Shape matches the dummy credential type's `claim_schema` seeded
    // by tenant bootstrap: `{ first_name, last_name }`, both required
    // strings.
    json!({
        "first_name": "Anna",
        "last_name": "Müller",
    })
}

fn log_issuer(issuer: &IssuerView) {
    tracing::info!(
        id = %issuer.id,
        did = %issuer.did,
        state = %issuer.state,
        description = %issuer.description,
        display_name = %issuer.display_name,
        "issuer view",
    );
}

// ---------------------------------------------------------------------------
// HTTP clients
// ---------------------------------------------------------------------------

struct Mgmt {
    base: String,
    http: Client,
}

impl Mgmt {
    fn new(base: &str, token: &str) -> Result<Self, reqwest::Error> {
        let mut headers = HeaderMap::new();
        let auth = HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("token contains only ascii bytes");
        headers.insert(AUTHORIZATION, auth);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            base: base.to_string(),
            http,
        })
    }

    async fn create_issuer(&self, display_name: &str) -> Result<CreateIssuerResponse, PhaseError> {
        let body = json!({ "display_name": display_name });
        self.post("/api/v1/issuers", &body, &[StatusCode::CREATED])
            .await
    }

    async fn get_issuer(&self, issuer_id: &str) -> Result<IssuerView, PhaseError> {
        self.get(&format!("/api/v1/issuers/{issuer_id}")).await
    }

    async fn get_task(&self, task_id: &str) -> Result<TaskStatus, PhaseError> {
        self.get(&format!("/api/v1/operation-tasks/{task_id}"))
            .await
    }

    async fn create_offer(
        &self,
        issuer_id: &str,
        credential_type_id: &str,
        claims: Value,
    ) -> Result<CreateOfferResponse, PhaseError> {
        let body = json!({
            "credential_type_id": credential_type_id,
            "claims": claims,
        });
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/credential-offers"),
            &body,
            &[StatusCode::CREATED],
        )
        .await
    }

    async fn find_credential_type_by_vct(
        &self,
        vct: &str,
    ) -> Result<CredentialTypeView, PhaseError> {
        let listing: ListCredentialTypesView = self.get("/api/v1/credential-types").await?;
        listing
            .items
            .into_iter()
            .find(|t| t.vct == vct)
            .ok_or_else(|| {
                assertion(format!(
                    "no credential type with vct {vct:?} found for the dev tenant; \
                     ensure bootstrap-dev-tenant has run",
                ))
            })
    }

    async fn assign_credential_type(
        &self,
        issuer_id: &str,
        credential_type_id: &str,
    ) -> Result<(), PhaseError> {
        // Idempotent on the API side: a second call on an already-
        // assigned (issuer, type) pair returns 200 OK; a fresh
        // assignment returns 201 Created.
        let _: serde_json::Value = self
            .post(
                &format!("/api/v1/issuers/{issuer_id}/credential-types/{credential_type_id}",),
                &serde_json::json!({}),
                &[StatusCode::CREATED, StatusCode::OK],
            )
            .await?;
        Ok(())
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &impl Serialize,
        accept: &[StatusCode],
    ) -> Result<T, PhaseError> {
        let url = format!("{}{}", self.base, path);
        let started = Instant::now();
        let body_text = serde_json::to_string(body)?;
        tracing::info!(method = "POST", %url, body = %body_text, "→ request");
        let response = self.http.post(&url).body(body_text).send().await?;
        let status = response.status();
        let text = response.text().await?;
        tracing::info!(
            method = "POST",
            %url,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            body = %pretty(&text),
            "← response",
        );
        if !accept.contains(&status) {
            return Err(PhaseError::Http(status, text));
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, PhaseError> {
        let url = format!("{}{}", self.base, path);
        let started = Instant::now();
        tracing::info!(method = "GET", %url, "→ request");
        let response: Response = self.http.get(&url).send().await?;
        let status = response.status();
        let text = response.text().await?;
        tracing::info!(
            method = "GET",
            %url,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            body = %pretty(&text),
            "← response",
        );
        if !status.is_success() {
            return Err(PhaseError::Http(status, text));
        }
        Ok(serde_json::from_str(&text)?)
    }
}

struct Oidc {
    base: String,
    http: Client,
}

impl Oidc {
    fn new(base: &str) -> Result<Self, reqwest::Error> {
        let http = Client::builder().build()?;
        Ok(Self {
            base: base.to_string(),
            http,
        })
    }

    async fn get_credential_offer(
        &self,
        issuer_id: &str,
        offer_id: &str,
    ) -> Result<Value, PhaseError> {
        let url = format!(
            "{}/i/{}/credential-offer/{}",
            self.base, issuer_id, offer_id
        );
        let started = Instant::now();
        tracing::info!(method = "GET", %url, "→ request");
        let response = self.http.get(&url).send().await?;
        let status = response.status();
        let text = response.text().await?;
        tracing::info!(
            method = "GET",
            %url,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            body = %pretty(&text),
            "← response",
        );
        if !status.is_success() {
            return Err(PhaseError::Http(status, text));
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn mint_token(
        &self,
        issuer_id: &str,
        pre_auth_code: &str,
    ) -> Result<TokenResponse, PhaseError> {
        let url = format!("{}/i/{}/token", self.base, issuer_id);
        // axum's `Form` extractor accepts standard
        // `application/x-www-form-urlencoded`; reqwest's own
        // `.form()` is gated behind a feature this crate does not
        // enable, so we hand-encode the two fields.
        let form = format!(
            "grant_type={}&pre-authorized_code={}",
            urlencoding::encode(PRE_AUTHORIZED_GRANT_TYPE),
            urlencoding::encode(pre_auth_code),
        );
        let started = Instant::now();
        tracing::info!(method = "POST", %url, form = %form, "→ request");
        let response = self
            .http
            .post(&url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        tracing::info!(
            method = "POST",
            %url,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            body = %pretty(&text),
            "← response",
        );
        if !status.is_success() {
            return Err(PhaseError::Http(status, text));
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn fetch_credential(
        &self,
        issuer_id: &str,
        access_token: &str,
        vct: &str,
        proof_jwt: &str,
    ) -> Result<String, PhaseError> {
        let url = format!("{}/i/{}/credential", self.base, issuer_id);
        let body = json!({
            "format": "vc+sd-jwt",
            "vct": vct,
            "proof": {
                "proof_type": "jwt",
                "jwt": proof_jwt,
            },
        });
        let body_text = serde_json::to_string(&body)?;
        let started = Instant::now();
        tracing::info!(method = "POST", %url, "→ request");
        let response = self
            .http
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(body_text)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        tracing::info!(
            method = "POST",
            %url,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            body = %pretty(&text),
            "← response",
        );
        if !status.is_success() {
            return Err(PhaseError::Http(status, text));
        }
        let parsed: CredentialResponse = serde_json::from_str(&text)?;
        Ok(parsed.credential)
    }
}

fn pretty(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string()),
        Err(_) => text.to_string(),
    }
}

async fn wait_until_completed(mgmt: &Mgmt, task_id: &str, cfg: &Config) -> Result<(), PhaseError> {
    let started = Instant::now();
    let deadline = started + cfg.task_timeout;
    let mut tick: u32 = 0;
    loop {
        tick += 1;
        let status = mgmt.get_task(task_id).await?;
        let last_state = status.state.clone();
        let elapsed_ms = started.elapsed().as_millis() as u64;
        tracing::info!(
            poll = tick,
            task_id = %status.id,
            task_type = %status.task_type,
            state = %status.state,
            step = ?status.step,
            attempts = status.attempts,
            next_attempt_at = ?status.next_attempt_at,
            elapsed_ms,
            "task poll",
        );
        match status.state.as_str() {
            "completed" => {
                tracing::info!(task_id = %status.id, "✓ task completed");
                return Ok(());
            }
            "failed" => {
                return Err(PhaseError::TaskFailed {
                    task_id: status.id,
                    code: status.error_code.unwrap_or_else(|| "<unset>".into()),
                    message: status.error_message.unwrap_or_else(|| "<unset>".into()),
                });
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(PhaseError::TaskTimeout {
                task_id: task_id.to_string(),
                timeout: cfg.task_timeout,
                last_state,
            });
        }
        sleep(cfg.poll_interval).await;
    }
}

async fn mint_smoke_token(database_url: &str) -> Result<String, PhaseError> {
    let pool = persistence::connect(database_url)
        .await
        .map_err(|e| PhaseError::Setup(format!("connect to {database_url}: {e}")))?;
    persistence::run_migrations(&pool)
        .await
        .map_err(|e| PhaseError::Setup(format!("run migrations: {e}")))?;
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| PhaseError::Setup(format!("acquire connection: {e}")))?;

    let partner_id_str = env::var("DEV_TENANT_PARTNER_ID")
        .map_err(|_| PhaseError::Setup("DEV_TENANT_PARTNER_ID must be set".into()))?;
    let partner_id: Uuid = partner_id_str
        .parse()
        .map_err(|e| PhaseError::Setup(format!("invalid DEV_TENANT_PARTNER_ID: {e}")))?;
    let tenant = persistence::tenants::find_by_partner_id(&mut conn, partner_id)
        .await
        .map_err(|e| PhaseError::Setup(format!("find tenant by partner_id: {e}")))?
        .ok_or_else(|| {
            PhaseError::Setup(format!(
                "no tenant with partner_id {partner_id}; run `swiyu-issuer-cli tenant bootstrap-dev-from-env` first"
            ))
        })?;
    let tenant_bare = tenant.id.bare().to_string();
    let secret = ApiTokenSecret::generate();
    let expires_at = Some(
        Utc::now()
            + chrono::Duration::from_std(SMOKE_TOKEN_TTL)
                .expect("SMOKE_TOKEN_TTL fits in chrono::Duration"),
    );
    let token = ApiToken::new(
        tenant.id,
        format!(
            "credential-lifecycle-smoke {}",
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        ),
        secret.hash(),
        expires_at,
    );

    persistence::api_tokens::insert(&mut conn, &token)
        .await
        .map_err(|e| PhaseError::Setup(format!("insert api_token row: {e}")))?;

    tracing::info!(
        token_id = %token.id,
        tenant = %tenant_bare,
        ttl_secs = SMOKE_TOKEN_TTL.as_secs(),
        "✓ smoke API token minted",
    );

    Ok(secret.as_wire())
}

// ---------------------------------------------------------------------------
// Wallet-side helpers
// ---------------------------------------------------------------------------

/// Builds a structurally- and cryptographically-valid OIDC4VCI
/// wallet proof JWT signed with the given Ed25519 wallet key. The
/// signing key stays in process memory only — fresh per smoke run.
fn build_wallet_proof(
    signing_key: &SigningKey,
    issuer_base_url: &str,
    issuer_id: &str,
    nonce: &str,
) -> Result<String, PhaseError> {
    let verifying_key = signing_key.verifying_key();
    let x_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let header = json!({
        "alg": "EdDSA",
        "typ": "openid4vci-proof+jwt",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
        },
    });
    let payload = json!({
        "aud": format!("{}/i/{}", issuer_base_url.trim_end_matches('/'), issuer_id),
        "iat": Utc::now().timestamp(),
        "nonce": nonce,
    });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{h}.{p}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let s = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{h}.{p}.{s}"))
}

fn extract_pre_auth_code(offer: &Value) -> Result<String, String> {
    offer
        .get("grants")
        .and_then(|g| g.get(PRE_AUTHORIZED_GRANT_TYPE))
        .and_then(|g| g.get("pre-authorized_code"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            "OIDC offer body is missing grants[pre-authorized_code][pre-authorized_code]"
                .to_string()
        })
}

// ---------------------------------------------------------------------------
// JWS verification against the published DID document
// ---------------------------------------------------------------------------

async fn fetch_didlog(did_str: &str) -> Result<String, PhaseError> {
    let did = DID::from_str(did_str).map_err(|e| PhaseError::Crypto(format!("parse did: {e}")))?;
    let url = did.log_url();
    tracing::info!(did = %did_str, %url, "→ public DID-log fetch");
    let response = reqwest::get(&url).await?;
    let status = response.status();
    let body = response.text().await?;
    tracing::info!(
        %url,
        status = status.as_u16(),
        bytes = body.len(),
        "← public DID-log fetch",
    );
    if !status.is_success() {
        return Err(PhaseError::Http(status, body));
    }
    Ok(body)
}

/// Pulls the assertion-method verification key out of the latest
/// DID-log entry's embedded DID document, parses it as a JWK, and
/// returns a `swiyu_core::jws::VerifyingKey` ready to verify the
/// credential's JWS. The handler always emits `kid =
/// {did}#assertion-key-01` (see `swiyu_core::diddoc::DIDDoc::new_genesis`)
/// so we look up that exact id.
fn extract_assertion_key(log: &DIDLog, did_str: &str) -> Result<VerifyingKey, String> {
    let entries = log.entries();
    let last = entries
        .last()
        .ok_or_else(|| "DID log is empty".to_string())?;
    let doc_value = match last.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => {
            return Err(
                "latest entry's did_doc_state is a JSON Patch (full snapshot expected)".to_string(),
            );
        }
    };
    let doc = DIDDoc::try_from(doc_value).map_err(|e| format!("parse DID doc: {e}"))?;

    let target_id = format!("{did_str}#assertion-key-01");
    let vm = doc
        .verification_method()
        .iter()
        .find(|vm| vm.id() == target_id)
        .ok_or_else(|| format!("DID doc has no verification method with id {target_id:?}"))?;

    match vm.public_key() {
        PublicKey::Jwk(jwk) => VerifyingKey::try_from(jwk.as_ref())
            .map_err(|e| format!("assertion-key jwk → VerifyingKey: {e}")),
        PublicKey::Multibase(_) => {
            Err("assertion-method VM is multibase; smoke expects publicKeyJwk".to_string())
        }
    }
}

fn verify_jws(credential: &str, key: &VerifyingKey) -> Result<(), PhaseError> {
    // SD-JWT VC: <header_b64>.<payload_b64>.<signature_b64>~
    let core = credential.trim_end_matches('~');
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(PhaseError::Crypto(format!(
            "expected three JWS segments, got {}",
            parts.len()
        )));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| PhaseError::Crypto(format!("signature segment is not base64url: {e}")))?;
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|e| PhaseError::Crypto(format!("signature did not verify: {e}")))
}
