use std::env;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};

use chrono::Utc;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use swiyu_core::did::DID;
use swiyu_issuer::domain::{ApiToken, ApiTokenSecret, TenantId};
use swiyu_issuer::persistence;
use thiserror::Error;
use tokio::time::sleep;

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_POLL_MS: u64 = 1000;

// Bare tenant id of the development tenant seeded by migration
// `20260430_000001_init.sql`. Every issuer the smoke creates is owned
// by this tenant.
const SEEDED_DEV_TENANT: &str = "4Mk7yK5pQR7sN3";

// Lifetime of the token the smoke mints at startup. Long enough for a
// slow or interactive run, short enough that orphaned rows expire on
// their own without manual cleanup.
const SMOKE_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

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

    tracing::info!(
        mgmt_url = %cfg.mgmt_url,
        timeout_secs = cfg.task_timeout.as_secs(),
        poll_ms = cfg.poll_interval.as_millis() as u64,
        "issuer-lifecycle-smoke starting",
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
    database_url: String,
    task_timeout: Duration,
    poll_interval: Duration,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        Ok(Self {
            mgmt_url: required("ISSUER_BASE_URL")?
                .trim_end_matches('/')
                .to_string(),
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
    #[error("DID `{0}` could not be parsed for registry lookup")]
    DidParse(String),
    #[error("setup: {0}")]
    Setup(String),
}

fn assertion(msg: impl Into<String>) -> PhaseError {
    PhaseError::Assertion(msg.into())
}

#[derive(Debug, Deserialize)]
struct CreateResponse {
    task_id: String,
    issuer_id: String,
}

#[derive(Debug, Deserialize)]
struct RotateResponse {
    task_id: String,
}

#[derive(Debug, Deserialize)]
struct DeactivateResponse {
    task_id: Option<String>,
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

async fn run(cfg: &Config) -> Result<(), SmokeError> {
    let token = mint_smoke_token(&cfg.database_url)
        .await
        .map_err(phase("init"))?;
    let mgmt = Mgmt::new(&cfg.mgmt_url, &token).map_err(|e| SmokeError::Phase {
        phase: "init",
        source: PhaseError::Transport(e),
    })?;

    // ---- Phase 1: create ----
    log_phase(1, "create_issuer");
    let display_name = format!(
        "lifecycle-smoke {}",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
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

    let initial_log = fetch_log(&issuer.did)
        .await
        .map_err(phase("create.didlog.fetch"))?;
    let initial_entries = parse_jsonl(&initial_log).map_err(phase("create.didlog.parse"))?;
    log_didlog_summary("after create", &initial_entries);
    if initial_entries.len() != 1 {
        return Err(SmokeError::Phase {
            phase: "create.didlog.assert",
            source: assertion(format!(
                "expected 1 DID log entry after create, got {}",
                initial_entries.len()
            )),
        });
    }

    // ---- Phase 2: fetch (already done above; this phase exists in the spec) ----
    log_phase(2, "fetch_issuer");
    tracing::info!("✓ issuer fetched (id={})", issuer.id);

    // ---- Phase 3: rotate ----
    log_phase(3, "rotate_keys");
    let rotate = mgmt
        .rotate_keys(&issuer.id, &["all"])
        .await
        .map_err(phase("rotate.submit"))?;
    tracing::info!(task_id = %rotate.task_id, "rotate-keys task submitted");

    wait_until_completed(&mgmt, &rotate.task_id, cfg)
        .await
        .map_err(phase("rotate.poll"))?;

    let after_rotate = fetch_log(&issuer.did)
        .await
        .map_err(phase("rotate.didlog.fetch"))?;
    let rotate_entries = parse_jsonl(&after_rotate).map_err(phase("rotate.didlog.parse"))?;
    log_didlog_summary("after rotate", &rotate_entries);
    if rotate_entries.len() < 2 {
        return Err(SmokeError::Phase {
            phase: "rotate.didlog.assert",
            source: assertion(format!(
                "expected ≥2 DID log entries after rotate, got {}",
                rotate_entries.len()
            )),
        });
    }
    let prev_keys = update_keys(&initial_entries[initial_entries.len() - 1]);
    let new_keys = update_keys(&rotate_entries[rotate_entries.len() - 1]);
    if prev_keys.is_some() && prev_keys == new_keys {
        return Err(SmokeError::Phase {
            phase: "rotate.didlog.assert",
            source: assertion("updateKeys did not change after rotate-keys task"),
        });
    }
    tracing::info!(
        prev_update_keys = ?prev_keys,
        new_update_keys = ?new_keys,
        "✓ updateKeys advanced",
    );

    // ---- Phase 4: deactivate ----
    log_phase(4, "deactivate_issuer");
    let deactivate = mgmt
        .deactivate(&issuer.id)
        .await
        .map_err(phase("deactivate.submit"))?;
    let task_id = deactivate.task_id.ok_or_else(|| SmokeError::Phase {
        phase: "deactivate.submit",
        source: assertion("deactivate response carried task_id=null on a fresh issuer"),
    })?;
    tracing::info!(task_id = %task_id, "deactivate-issuer task submitted");

    wait_until_completed(&mgmt, &task_id, cfg)
        .await
        .map_err(phase("deactivate.poll"))?;

    let final_issuer = mgmt
        .get_issuer(&issuer.id)
        .await
        .map_err(phase("deactivate.fetch"))?;
    log_issuer(&final_issuer);
    if final_issuer.state != "deactivated" {
        return Err(SmokeError::Phase {
            phase: "deactivate.assert",
            source: assertion(format!(
                "expected issuer state=deactivated, got {}",
                final_issuer.state
            )),
        });
    }

    let final_log = fetch_log(&issuer.did)
        .await
        .map_err(phase("deactivate.didlog.fetch"))?;
    let final_entries = parse_jsonl(&final_log).map_err(phase("deactivate.didlog.parse"))?;
    log_didlog_summary("after deactivate", &final_entries);
    if final_entries.len() <= rotate_entries.len() {
        return Err(SmokeError::Phase {
            phase: "deactivate.didlog.assert",
            source: assertion(format!(
                "expected DID log to grow on deactivate; was {} entries, now {}",
                rotate_entries.len(),
                final_entries.len()
            )),
        });
    }
    if !is_deactivated(&final_entries[final_entries.len() - 1]) {
        return Err(SmokeError::Phase {
            phase: "deactivate.didlog.assert",
            source: assertion("tail DID log entry does not carry parameters.deactivated=true"),
        });
    }
    tracing::info!("✓ DID log tail entry has deactivated=true");

    Ok(())
}

fn phase(name: &'static str) -> impl FnOnce(PhaseError) -> SmokeError {
    move |source| SmokeError::Phase {
        phase: name,
        source,
    }
}

fn log_phase(n: u8, name: &str) {
    tracing::info!("=== Phase {n}/4: {name} ===");
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

fn log_didlog_summary(label: &str, entries: &[Value]) {
    let count = entries.len();
    let tail_version_id = entries
        .last()
        .and_then(|e| e.get(0))
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    tracing::info!(
        entries = count,
        tail_versionId = tail_version_id,
        "DID log {label}",
    );
}

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

    async fn create_issuer(&self, display_name: &str) -> Result<CreateResponse, PhaseError> {
        let body = json!({ "display_name": display_name });
        self.post("/api/v1/issuers", &body, &[StatusCode::CREATED])
            .await
    }

    async fn rotate_keys(
        &self,
        issuer_id: &str,
        roles: &[&str],
    ) -> Result<RotateResponse, PhaseError> {
        let body = json!({ "roles": roles });
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/rotate-keys"),
            &body,
            &[StatusCode::CREATED, StatusCode::OK],
        )
        .await
    }

    async fn deactivate(&self, issuer_id: &str) -> Result<DeactivateResponse, PhaseError> {
        let body = json!({});
        self.post(
            &format!("/api/v1/issuers/{issuer_id}/deactivate"),
            &body,
            &[StatusCode::CREATED, StatusCode::OK],
        )
        .await
    }

    async fn get_issuer(&self, issuer_id: &str) -> Result<IssuerView, PhaseError> {
        self.get(&format!("/api/v1/issuers/{issuer_id}")).await
    }

    async fn get_task(&self, task_id: &str) -> Result<TaskStatus, PhaseError> {
        self.get(&format!("/api/v1/operation-tasks/{task_id}"))
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

    let tenant_id = TenantId::from_bare(SEEDED_DEV_TENANT)
        .map_err(|e| PhaseError::Setup(format!("invalid SEEDED_DEV_TENANT: {e}")))?;
    let secret = ApiTokenSecret::generate();
    let expires_at = Some(
        Utc::now()
            + chrono::Duration::from_std(SMOKE_TOKEN_TTL)
                .expect("SMOKE_TOKEN_TTL fits in chrono::Duration"),
    );
    let token = ApiToken::new(
        tenant_id,
        format!(
            "issuer-lifecycle-smoke {}",
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
        tenant = SEEDED_DEV_TENANT,
        ttl_secs = SMOKE_TOKEN_TTL.as_secs(),
        "✓ smoke API token minted",
    );

    Ok(secret.as_wire())
}

// The DID encodes its own resolver location: `did:tdw:{scid}:{host}:{path}`
// maps to `https://{host}/{path}/did.jsonl`. We hit that URL directly
// rather than reusing the partner-write registry client, because on
// SWIYU integration the read endpoint lives on a different host
// (identifier-reg.* vs identifier-reg-api.*) and a verifier in the
// wild only has the DID — no env config — to work from.
async fn fetch_log(did: &str) -> Result<String, PhaseError> {
    let parsed = DID::from_str(did).map_err(|_| PhaseError::DidParse(did.into()))?;
    let url = parsed.log_url();
    tracing::info!(did = %did, %url, "→ public DID-log fetch");
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

fn parse_jsonl(body: &str) -> Result<Vec<Value>, PhaseError> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).map_err(PhaseError::Json))
        .collect()
}

fn update_keys(entry: &Value) -> Option<Vec<String>> {
    let params = entry.get(2)?.as_object()?;
    let keys = params.get("updateKeys")?.as_array()?;
    Some(
        keys.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
    )
}

fn is_deactivated(entry: &Value) -> bool {
    entry
        .get(2)
        .and_then(|p| p.get("deactivated"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
