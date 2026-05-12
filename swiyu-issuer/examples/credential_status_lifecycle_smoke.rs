use std::env;
use std::process::ExitCode;
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
use swiyu_core::statuslist::{StatusListJwtPayload, StatusValue};
use swiyu_issuer::domain::{ApiToken, ApiTokenSecret};
use swiyu_issuer::persistence;
use thiserror::Error;
use tokio::time::sleep;
use uuid::Uuid;

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_POLL_MS: u64 = 1000;

const SMOKE_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

const FIXTURE_VCT: &str = "urn:communal:local-residence-id";
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
        "credential-status-lifecycle-smoke starting",
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
    mgmt_url: String,
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
    #[error(
        "registry status at idx={idx} did not reach {expected:?} within {timeout:?} (last={last:?})"
    )]
    RegistryTimeout {
        idx: u64,
        expected: &'static str,
        timeout: Duration,
        last: String,
    },
    #[error("assertion: {0}")]
    Assertion(String),
    #[error("setup: {0}")]
    Setup(String),
    #[error("decode: {0}")]
    Decode(String),
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
    tracing::info!("=== Phase {n}/8: {name} ===");
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
struct TokenResponse {
    access_token: String,
    token_type: String,
    c_nonce: String,
}

#[derive(Debug, Deserialize)]
struct CredentialResponse {
    credential: String,
}

#[derive(Debug, Deserialize)]
struct IssuedCredentialView {
    id: String,
    credential_offer_id: String,
    status_list_id: String,
    status_list_index: u32,
    state: String,
}

#[derive(Debug, Deserialize)]
struct ListIssuedCredentialsResponse {
    items: Vec<IssuedCredentialView>,
    #[allow(dead_code)]
    next_cursor: Option<String>,
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
    let public = PublicHttp::new().map_err(|e| SmokeError::Phase {
        phase: "init",
        source: PhaseError::Transport(e),
    })?;

    // ---- Phase 1: create issuer ----
    log_phase(1, "create_issuer");
    let display_name = format!(
        "credential-status-lifecycle-smoke {}",
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

    // ---- Phase 2: create credential offer ----
    log_phase(2, "create_offer");
    let offer = mgmt
        .create_offer(&create.issuer_id, FIXTURE_VCT, fixture_claims())
        .await
        .map_err(phase("offer.submit"))?;
    tracing::info!(
        offer_id = %offer.id,
        deeplink = %offer.offer_deeplink,
        expires_at = %offer.expires_at,
        "credential offer created",
    );

    // ---- Phase 3: wallet — fetch offer / mint token / fetch credential ----
    log_phase(3, "wallet_consume_offer");
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
            FIXTURE_VCT,
            &proof_jwt,
        )
        .await
        .map_err(phase("wallet.credential"))?;
    tracing::info!(bytes = credential.len(), "✓ credential issued");

    // ---- Phase 4: locate credential in the management API ----
    log_phase(4, "locate_credential");
    let pointer = read_status_pointer(&credential).map_err(|m| SmokeError::Phase {
        phase: "locate.status_claim",
        source: PhaseError::Decode(m),
    })?;
    tracing::info!(
        idx = pointer.idx,
        uri = %pointer.uri,
        "extracted status pointer from issued credential",
    );
    let credentials = mgmt
        .list_issued_credentials(&create.issuer_id)
        .await
        .map_err(phase("locate.list"))?;
    let issued = credentials
        .items
        .into_iter()
        .find(|c| c.credential_offer_id == offer.id)
        .ok_or_else(|| SmokeError::Phase {
            phase: "locate.match",
            source: assertion(format!(
                "no issued credential row found for offer_id={}",
                offer.id
            )),
        })?;
    if issued.state != "active" {
        return Err(SmokeError::Phase {
            phase: "locate.assert",
            source: assertion(format!(
                "expected credential state=active just after issuance, got {}",
                issued.state
            )),
        });
    }
    if u64::from(issued.status_list_index) != pointer.idx {
        return Err(SmokeError::Phase {
            phase: "locate.assert",
            source: assertion(format!(
                "credential row index ({}) disagrees with status claim idx ({})",
                issued.status_list_index, pointer.idx
            )),
        });
    }
    tracing::info!(
        credential_id = %issued.id,
        status_list_id = %issued.status_list_id,
        index = issued.status_list_index,
        "credential row located",
    );

    // ---- Phase 5: registry baseline = Valid ----
    log_phase(5, "registry_baseline");
    wait_for_registry_status(&public, &pointer, StatusValue::Valid, cfg)
        .await
        .map_err(phase("baseline.registry"))?;
    tracing::info!("✓ registry shows status=Valid for newly-issued credential");

    // ---- Phase 6: suspend ----
    log_phase(6, "suspend");
    let suspended = mgmt
        .suspend(&create.issuer_id, &issued.id)
        .await
        .map_err(phase("suspend.submit"))?;
    if suspended.state != "suspended" {
        return Err(SmokeError::Phase {
            phase: "suspend.assert.local",
            source: assertion(format!(
                "expected credential state=suspended after suspend, got {}",
                suspended.state
            )),
        });
    }
    wait_for_registry_status(&public, &pointer, StatusValue::Suspended, cfg)
        .await
        .map_err(phase("suspend.registry"))?;
    tracing::info!("✓ registry shows status=Suspended");

    // ---- Phase 7: unsuspend ----
    log_phase(7, "unsuspend");
    let unsuspended = mgmt
        .unsuspend(&create.issuer_id, &issued.id)
        .await
        .map_err(phase("unsuspend.submit"))?;
    if unsuspended.state != "active" {
        return Err(SmokeError::Phase {
            phase: "unsuspend.assert.local",
            source: assertion(format!(
                "expected credential state=active after unsuspend, got {}",
                unsuspended.state
            )),
        });
    }
    wait_for_registry_status(&public, &pointer, StatusValue::Valid, cfg)
        .await
        .map_err(phase("unsuspend.registry"))?;
    tracing::info!("✓ registry shows status=Valid again after unsuspend");

    // ---- Phase 8: revoke ----
    log_phase(8, "revoke");
    let revoked = mgmt
        .revoke(&create.issuer_id, &issued.id)
        .await
        .map_err(phase("revoke.submit"))?;
    if revoked.state != "revoked" {
        return Err(SmokeError::Phase {
            phase: "revoke.assert.local",
            source: assertion(format!(
                "expected credential state=revoked after revoke, got {}",
                revoked.state
            )),
        });
    }
    wait_for_registry_status(&public, &pointer, StatusValue::Revoked, cfg)
        .await
        .map_err(phase("revoke.registry"))?;
    tracing::info!("✓ registry shows status=Revoked");

    Ok(())
}

fn fixture_claims() -> Value {
    json!({
        "family_name": "Müller",
        "given_name": "Anna",
        "birth_date": "1990-04-15",
        "commune_bfs": 3203,
        "commune_name": "Bern",
        "valid_until": "2030-12-31",
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
        vct: &str,
        claims: Value,
    ) -> Result<CreateOfferResponse, PhaseError> {
        let body = json!({
            "vct": vct,
            "claims": claims,
        });
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/credential-offers"),
            &body,
            &[StatusCode::CREATED],
        )
        .await
    }

    async fn list_issued_credentials(
        &self,
        issuer_id: &str,
    ) -> Result<ListIssuedCredentialsResponse, PhaseError> {
        self.get(&format!("/api/v1/issuers/{issuer_id}/credentials"))
            .await
    }

    async fn suspend(
        &self,
        issuer_id: &str,
        credential_id: &str,
    ) -> Result<IssuedCredentialView, PhaseError> {
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/credentials/{credential_id}/suspend"),
            &json!({}),
            &[StatusCode::OK],
        )
        .await
    }

    async fn unsuspend(
        &self,
        issuer_id: &str,
        credential_id: &str,
    ) -> Result<IssuedCredentialView, PhaseError> {
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/credentials/{credential_id}/unsuspend"),
            &json!({}),
            &[StatusCode::OK],
        )
        .await
    }

    async fn revoke(
        &self,
        issuer_id: &str,
        credential_id: &str,
    ) -> Result<IssuedCredentialView, PhaseError> {
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/credentials/{credential_id}/revoke"),
            &json!({}),
            &[StatusCode::OK],
        )
        .await
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

// Public-internet client used to fetch the published status-list JWT
// from the SWIYU registry. The URI lives in the credential's signed
// `status` claim, mirroring what an external verifier would dereference.
struct PublicHttp {
    http: Client,
}

impl PublicHttp {
    fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: Client::builder().build()?,
        })
    }

    async fn fetch_text(&self, url: &str) -> Result<String, PhaseError> {
        let started = Instant::now();
        tracing::debug!(method = "GET", %url, "→ public registry fetch");
        let response = self.http.get(url).send().await?;
        let status = response.status();
        let text = response.text().await?;
        tracing::debug!(
            method = "GET",
            %url,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            bytes = text.len(),
            "← public registry fetch",
        );
        if !status.is_success() {
            return Err(PhaseError::Http(status, text));
        }
        Ok(text)
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
            "credential-status-lifecycle-smoke {}",
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
// Wallet-side helpers (duplicated from credential_lifecycle_smoke)
// ---------------------------------------------------------------------------

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
// Status-list extraction & registry verification
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct StatusPointer {
    idx: u64,
    uri: String,
}

fn read_status_pointer(credential: &str) -> Result<StatusPointer, String> {
    // SD-JWT VC: <header>.<payload>.<signature>~  (we want the payload).
    let core = credential.trim_end_matches('~');
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("expected 3 JWS segments, got {}", parts.len()));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("payload segment is not base64url: {e}"))?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload is not JSON: {e}"))?;
    let status_list = payload
        .get("status")
        .and_then(|s| s.get("status_list"))
        .ok_or_else(|| "credential payload is missing status.status_list".to_string())?;
    let idx = status_list
        .get("idx")
        .and_then(Value::as_u64)
        .ok_or_else(|| "status.status_list.idx missing or not an integer".to_string())?;
    let uri = status_list
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "status.status_list.uri missing or not a string".to_string())?
        .to_string();
    Ok(StatusPointer { idx, uri })
}

async fn wait_for_registry_status(
    public: &PublicHttp,
    pointer: &StatusPointer,
    expected: StatusValue,
    cfg: &Config,
) -> Result<(), PhaseError> {
    let started = Instant::now();
    let deadline = started + cfg.task_timeout;
    let mut tick: u32 = 0;
    loop {
        tick += 1;
        let last_seen = match read_registry_status(public, pointer).await {
            Ok(value) => {
                let label = describe_status(value);
                tracing::info!(
                    poll = tick,
                    uri = %pointer.uri,
                    idx = pointer.idx,
                    seen = %label,
                    expected = %describe_status(expected),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "registry status poll",
                );
                if status_eq(value, expected) {
                    return Ok(());
                }
                label
            }
            Err(err) => {
                let label = format!("error: {err}");
                tracing::warn!(
                    poll = tick,
                    uri = %pointer.uri,
                    error = %err,
                    "registry status poll failed; will retry",
                );
                label
            }
        };
        if Instant::now() >= deadline {
            return Err(PhaseError::RegistryTimeout {
                idx: pointer.idx,
                expected: status_label(expected),
                timeout: cfg.task_timeout,
                last: last_seen,
            });
        }
        sleep(cfg.poll_interval).await;
    }
}

async fn read_registry_status(
    public: &PublicHttp,
    pointer: &StatusPointer,
) -> Result<StatusValue, PhaseError> {
    let jwt = public.fetch_text(&pointer.uri).await?;
    let parts: Vec<&str> = jwt.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(PhaseError::Decode(format!(
            "status-list JWT has {} segments, expected 3",
            parts.len()
        )));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| PhaseError::Decode(format!("payload not base64url: {e}")))?;
    let payload_value: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| PhaseError::Decode(format!("payload not JSON: {e}")))?;
    let payload = StatusListJwtPayload::try_from(&payload_value)
        .map_err(|e| PhaseError::Decode(format!("payload is not a status-list JWT: {e}")))?;
    let value = payload
        .list()
        .value_at(pointer.idx)
        .map_err(|e| PhaseError::Decode(format!("value_at({}) failed: {e}", pointer.idx)))?;
    Ok(value)
}

fn status_eq(a: StatusValue, b: StatusValue) -> bool {
    u8::from(a) == u8::from(b)
}

fn status_label(value: StatusValue) -> &'static str {
    match value {
        StatusValue::Valid => "Valid",
        StatusValue::Revoked => "Revoked",
        StatusValue::Suspended => "Suspended",
        StatusValue::Reserved(_) => "Reserved",
    }
}

fn describe_status(value: StatusValue) -> String {
    match value {
        StatusValue::Reserved(n) => format!("Reserved({n})"),
        other => status_label(other).to_string(),
    }
}
