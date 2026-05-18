use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body for `POST /api/v1/issuers`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssuerSubmission {
    /// Defaults to `""` when omitted.
    pub description: Option<String>,
    /// Defaults to `Issuer <id>` when omitted.
    pub display_name: Option<String>,
}

/// Response body returned by `POST /api/v1/issuers` on success (HTTP 201).
#[derive(Debug, Serialize)]
pub struct CreateIssuerResponse {
    /// Poll handle; use `GET /api/v1/operation-tasks/{task_id}` to track the saga.
    pub task_id: String,
    /// Generated server-side. `GET /api/v1/issuers/{id}` returns 404 until the
    /// task completes.
    pub issuer_id: String,
}

/// Response body returned by `POST /api/v1/issuers/{issuer_id}/rotate-keys`.
#[derive(Debug, Serialize)]
pub struct RotateKeysResponse {
    /// Always present: a fresh task (HTTP 201) or the existing in-flight one
    /// (HTTP 200).
    pub task_id: String,
    pub issuer_id: String,
}

/// Response body returned by `POST /api/v1/issuers/{issuer_id}/deactivate`.
#[derive(Debug, Serialize)]
pub struct DeactivateIssuerResponse {
    /// `Some` when a task drove the deactivation (fresh or already in-flight);
    /// `None` when the issuer is already `Deactivated` with no associated task row.
    pub task_id: Option<String>,
    pub issuer_id: String,
}

/// Response body returned by `GET /api/v1/issuers/{issuer_id}` on
/// success (HTTP 200).
#[derive(Debug, Serialize)]
pub struct GetIssuerResponse {
    pub id: String,
    pub did: String,
    /// Lifecycle state: `"active"` or `"deactivated"`.
    pub state: String,
    /// Empty string when no description was supplied at creation.
    pub description: String,
    /// Defaults to `Issuer <id>` when no display name was supplied at creation.
    pub display_name: String,
}

/// Query parameters for `GET /api/v1/issuers`.
#[derive(Debug, Deserialize)]
pub struct ListIssuersQuery {
    /// Page size. Bounded at the handler; out-of-range values yield `invalid_input`.
    pub limit: Option<u32>,
    /// Opaque cursor from the previous page's `next_cursor`. The handler rejects
    /// anything it did not itself emit.
    pub cursor: Option<String>,
}

/// Response body returned by `GET /api/v1/issuers` on success
/// (HTTP 200).
#[derive(Debug, Serialize)]
pub struct ListIssuersResponse {
    pub items: Vec<GetIssuerResponse>,
    /// Opaque token to pass as `cursor` on the next request; `None` when this
    /// page exhausts the tenant's issuers.
    pub next_cursor: Option<String>,
}

/// Response body returned by `GET /api/v1/operation-tasks/{task_id}`
/// on success (HTTP 200).
#[derive(Debug, Serialize)]
pub struct GetOperationTaskResponse {
    pub id: String,
    /// One of `"create_issuer"`, `"deactivate_issuer"`, `"rotate_keys"`.
    pub task_type: String,
    /// Saga state: `"pending"`, `"in_progress"`, `"completed"`, or `"failed"`.
    pub state: String,
    /// Current saga step within the operation; `None` when the task has not
    /// started yet.
    pub step: Option<String>,
    pub attempts: u32,
    /// When the next retry is scheduled; `None` when the task is active or
    /// terminal.
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// Set on terminal failure; `None` while the task is pending or in progress.
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request body for `POST /api/v1/issuers/{issuer_id}/credential-offers`.
#[derive(Debug, Deserialize)]
pub struct CreateCredentialOfferRequest {
    /// SD-JWT VC type identifier (URI). Selects the JSON Schema used to
    /// validate `claims`; unknown values return HTTP 400.
    pub vct: String,
    pub claims: Value,
    /// Offer lifetime in seconds. The handler applies a configured default when
    /// omitted and rejects values outside the configured bounds.
    pub expires_in_seconds: Option<u32>,
}

/// Response body returned by `POST .../credential-offers` on success (HTTP 201).
#[derive(Debug, Serialize)]
pub struct CreateCredentialOfferResponse {
    pub id: String,
    /// Bare OID4VCI pre-authorisation secret, returned exactly once. Only its
    /// hash is persisted — this is the caller's only opportunity to capture it.
    pub pre_auth_code: String,
    /// `openid-credential-offer://` URI, suitable for a QR code or direct
    /// handoff to a holder wallet.
    pub offer_deeplink: String,
    pub expires_at: DateTime<Utc>,
}

/// Response body returned by `GET .../credential-offers/{offer_id}` on success
/// (HTTP 200).
#[derive(Debug, Serialize)]
pub struct GetCredentialOfferResponse {
    pub id: String,
    pub issuer_id: String,
    /// SD-JWT VC type identifier (URI).
    pub vct: String,
    pub claims: Value,
    /// Observed state: a stored-`pending` row past `expires_at` surfaces as
    /// `"expired"` without a database update.
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Response body returned by `GET .../credential-offers/{offer_id}/status` on
/// success (HTTP 200).
#[derive(Debug, Serialize)]
pub struct OfferStatusResponse {
    pub id: String,
    /// Observed state; same semantics as `state` in `GetCredentialOfferResponse`.
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Query parameters for `GET .../credential-offers`.
#[derive(Debug, Deserialize)]
pub struct ListCredentialOffersQuery {
    /// Page size. Bounded at the handler; out-of-range values yield `invalid_input`.
    pub limit: Option<u32>,
    /// Opaque cursor from the previous page's `next_cursor`. The handler rejects
    /// anything it did not itself emit.
    pub cursor: Option<String>,
    /// Filter on the observed state. `"expired"` matches stored-`pending` rows past
    /// `expires_at`; `"pending"` matches those still within it.
    pub state: Option<String>,
}

/// Response body returned by `GET .../credential-offers` on success (HTTP 200).
#[derive(Debug, Serialize)]
pub struct ListCredentialOffersResponse {
    pub items: Vec<GetCredentialOfferResponse>,
    /// Opaque token to pass as `cursor` on the next request; `None` when this
    /// page exhausts the issuer's offers.
    pub next_cursor: Option<String>,
}

/// Query parameters for `GET /api/v1/issuers/{issuer_id}/credentials`.
#[derive(Debug, Deserialize)]
pub struct ListIssuedCredentialsQuery {
    /// Page size. Bounded at the handler to `1..=100`; out-of-range
    /// values yield `invalid_input`. Defaults to 25 when omitted.
    pub limit: Option<u32>,

    /// Opaque cursor returned as `next_cursor` from the previous
    /// page. Omit on the first request. The handler rejects anything
    /// it did not itself emit.
    pub cursor: Option<String>,

    /// Filter on the **stored** lifecycle state, one of `active`,
    /// `suspended`, `revoked`. The derived `expired` view is
    /// intentionally not a filter — it would force a server-side
    /// projection over `expires_at` against `now()` and would not
    /// align with any persisted value; passing `state=expired`
    /// returns `400 invalid_input`.
    pub state: Option<String>,

    /// Exact-match filter on the SD-JWT VC type identifier (URI).
    pub vct: Option<String>,
}

/// Response body returned by issued-credential lifecycle handlers (`suspend`,
/// `unsuspend`, `revoke`) and by the GET endpoints (`get` and `list`).
#[derive(Debug, Serialize)]
pub struct GetIssuedCredentialResponse {
    pub id: String,
    pub issuer_id: String,
    pub credential_offer_id: String,
    /// SD-JWT VC type identifier (URI).
    pub vct: String,
    /// RFC 7638 base64url thumbprint of the wallet's `cnf` key.
    pub holder_key_jkt: String,
    /// URI of the status list that carries this credential's revocation bit.
    pub status_list_id: String,
    /// Index into the status list.
    pub status_list_index: u32,
    /// Stored lifecycle state: `"active"`, `"suspended"`, or `"revoked"`.
    pub state: String,
    /// `true` when `expires_at` is in the past. Derived; never stored as a state.
    pub expired: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Response body returned by `GET /api/v1/issuers/{issuer_id}/credentials` on
/// success (HTTP 200).
#[derive(Debug, Serialize)]
pub struct ListIssuedCredentialsResponse {
    pub items: Vec<GetIssuedCredentialResponse>,
    /// Opaque token to pass as `cursor` on the next request; `None` when this
    /// page exhausts the issuer's credentials.
    pub next_cursor: Option<String>,
}

/// Request body for `POST /api/v1/credential-types`.
///
/// Carries the full structured-field set plus the `claim_schema`
/// document. Invalid JSON Schema documents are rejected with HTTP
/// 400 at create time.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredentialTypeRequest {
    /// SD-JWT VC type identifier (URI). Burned into every issued
    /// credential's `vct` claim. Unique within the tenant.
    pub vct: String,
    /// JSON Schema 2020-12 document validating the credential's
    /// application-level claims. Required: a row without a schema
    /// cannot validate at issuance.
    pub claim_schema: Value,
    /// OID4VCI claims metadata; surfaced verbatim in the issuer
    /// metadata projection. Defaults to `{}` when omitted.
    pub claims: Option<Value>,
    /// OID4VCI display array (per-locale entries); surfaced verbatim
    /// in the issuer metadata projection. Defaults to `[]` when
    /// omitted.
    pub display: Option<Value>,
    /// Admin-facing description; never reaches wallets.
    pub internal_description: Option<String>,
    /// Provenance URL the schema was fetched from; the system does
    /// not auto-refresh from it.
    pub claim_schema_source_url: Option<String>,
    /// Default validity window for credentials minted under this
    /// type, in seconds. Required; the issuance handler applies no
    /// fallback.
    pub default_validity_seconds: u64,
    /// One of `"revocable"`, `"suspendable"`,
    /// `"revocable_and_suspendable"`, `"none"`.
    pub revocation_mode: String,
}

/// Response body returned by `POST /api/v1/credential-types` on
/// success (HTTP 201).
#[derive(Debug, Serialize)]
pub struct CreateCredentialTypeResponse {
    /// The newly-assigned credential-type id (bs58 form, no
    /// `ctype_` prefix on the wire).
    pub credential_type_id: String,
}

/// Response body returned by the credential-type `GET` endpoints.
///
/// The three blob columns (`claim_schema`, `display`, `claims`) are
/// **not** embedded; they are fetched via their dedicated per-blob
/// endpoints. This keeps the list page small even on tenants with
/// large schemas.
#[derive(Debug, Serialize)]
pub struct GetCredentialTypeResponse {
    pub credential_type_id: String,
    pub vct: String,
    pub internal_description: Option<String>,
    pub claim_schema_source_url: Option<String>,
    pub claim_schema_fetched_at: Option<DateTime<Utc>>,
    pub default_validity_seconds: u64,
    pub revocation_mode: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// `Some(ts)` when retired; `None` while active.
    pub retired_at: Option<DateTime<Utc>>,
}

/// Query parameters for `GET /api/v1/credential-types`.
#[derive(Debug, Deserialize)]
pub struct ListCredentialTypesQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    /// `true` includes retired rows; defaults to `false` (the hot
    /// path the partial index serves).
    #[serde(default)]
    pub retired: bool,
}

/// Response body returned by `GET /api/v1/credential-types` on
/// success (HTTP 200).
#[derive(Debug, Serialize)]
pub struct ListCredentialTypesResponse {
    pub items: Vec<GetCredentialTypeResponse>,
    pub next_cursor: Option<String>,
}

/// Request body for `PATCH /api/v1/credential-types/{id}`.
///
/// Every field is optional; omitted fields are unchanged. Updates
/// to `claim_schema` / `display` / `claims` go through the
/// dedicated per-blob endpoints, not this PATCH.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchCredentialTypeRequest {
    pub vct: Option<String>,
    pub internal_description: Option<String>,
    pub claim_schema_source_url: Option<String>,
    pub default_validity_seconds: Option<u64>,
    pub revocation_mode: Option<String>,
}

/// Response body returned by `POST /api/v1/credential-types/{id}/retire`.
#[derive(Debug, Serialize)]
pub struct RetireCredentialTypeResponse {
    pub credential_type_id: String,
    pub retired_at: DateTime<Utc>,
}
