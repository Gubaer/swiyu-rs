use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body for `POST /api/v1/issuers`.
///
/// The BA-supplied portion of a `CreateIssuer` operation task. The
/// rest (DID, key triple, lifecycle state) is produced server-side
/// by the worker. Multi-tenant routing is resolved from the API
/// token by `TenantContext`, never from the body.
///
/// Both fields are optional. The handler applies defaults when a
/// field is missing or trims to an empty string: `description`
/// becomes `""`; `display_name` becomes `Issuer <bare-issuer-id>`
/// using the freshly generated `IssuerId`.
///
/// Distinct from `worker::create_issuer::CreateIssuerInput` (the
/// internal worker DTO) so the wire shape can diverge — e.g. when
/// `did_method` returns once `did:webvh` is testable end-to-end.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssuerSubmission {
    pub description: Option<String>,
    pub display_name: Option<String>,
}

/// Response body returned by `POST /api/v1/issuers` on success
/// (HTTP 201).
///
/// `task_id` is for polling the saga status. `issuer_id` is
/// generated server-side at submit time and pinned in
/// `task.result_issuer_id`; the BA can hit `/api/v1/issuers/{id}`
/// with it immediately and gets 404 until the task reaches
/// `Completed`.
#[derive(Debug, Serialize)]
pub struct CreateIssuerResponse {
    pub task_id: String,
    pub issuer_id: String,
}

/// Response body returned by
/// `POST /api/v1/issuers/{issuer_id}/deactivate`.
///
/// `task_id` is `Some` for fresh deactivations (HTTP 201, the new
/// task) and for already-pending or already-completed deactivations
/// where the originating task row is still findable (HTTP 200,
/// returned for poll-handle continuity). It is `None` only when the
/// issuer is `Deactivated` but no `DeactivateIssuer` task row drove
/// the transition — typically a directly-mutated fixture row.
/// `issuer_id` always echoes the path parameter.
#[derive(Debug, Serialize)]
pub struct DeactivateIssuerResponse {
    pub task_id: Option<String>,
    pub issuer_id: String,
}

/// Response body returned by `GET /api/v1/issuers/{issuer_id}` on
/// success (HTTP 200).
///
/// Carries the BA-facing projection of an issuer. Deliberately
/// omits:
///
/// - `tenant_id` — the BA already knows their tenant (it's bound to
///   the API token), so echoing it adds noise without information.
/// - `authorized_key_id` / `authentication_key_id` /
///   `assertion_key_id` — these are internal SigningEngine handles
///   the BA cannot act on, so exposing them is implementation leak.
/// - `signing_key_id`, `logo_uri`, `locale` — legacy transitional
///   fields, removed with the OIDC migration.
///
/// The seeded dev row from migration 0004 lacks `state` and is
/// filtered out by the handler with a 404 — every issuer that lands
/// in this DTO has the fields below set, so they appear without
/// `Option<…>` wrappers.
#[derive(Debug, Serialize)]
pub struct GetIssuerResponse {
    pub id: String,
    pub did: String,
    pub state: String,
    pub description: String,
    pub display_name: String,
}

/// Query parameters for `GET /api/v1/issuers`.
///
/// All fields are optional. `limit` is bounded at the handler;
/// out-of-range values yield `invalid_input`. `cursor` is opaque to
/// clients — the handler rejects anything it did not itself emit.
#[derive(Debug, Deserialize)]
pub struct ListIssuersQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

/// Response body returned by `GET /api/v1/issuers` on success
/// (HTTP 200).
///
/// `next_cursor` is `None` when the current page exhausts the
/// tenant's issuers; otherwise it carries the opaque token to pass
/// back as the next request's `cursor`.
#[derive(Debug, Serialize)]
pub struct ListIssuersResponse {
    pub items: Vec<GetIssuerResponse>,
    pub next_cursor: Option<String>,
}

/// Response body returned by `GET /api/v1/operation-tasks/{task_id}`
/// on success (HTTP 200).
///
/// BA-facing projection of an `OperationTask`. Surfaces the polling
/// fields a business application needs to track a long-running
/// operation: `state` and `step` for "where in the saga we are",
/// `attempts` / `next_attempt_at` / `error_*` for visibility into
/// retry behaviour, and the lifecycle timestamps.
///
/// Deliberately omits:
///
/// - `tenant_id` — bound to the API token, redundant on the wire.
/// - `input` — the BA submitted it, no need to echo it back.
/// - `state_data` — internal saga progress (DID, key handles), not
///   part of the BA-facing contract.
/// - `result_issuer_id` — the BA already received `issuer_id` in
///   the response to `POST /api/v1/issuers`; echoing it here would
///   add nothing.
#[derive(Debug, Serialize)]
pub struct GetOperationTaskResponse {
    pub id: String,
    pub task_type: String,
    pub state: String,
    pub step: Option<String>,
    pub attempts: u32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request body for creating a credential offer.
///
/// Submitted by a business application to
/// `POST /api/v1/issuers/{issuer_id}/credential-offers`. The `vct`
/// selects which JSON Schema validates `claims`; unknown values
/// return HTTP 400. `expires_in_seconds` is optional; the handler
/// applies a default and rejects values outside the configured
/// bounds. See `specs/impl_api_management.md` for the full
/// contract.
#[derive(Debug, Deserialize)]
pub struct CreateCredentialOfferRequest {
    pub vct: String,
    pub claims: Value,
    pub expires_in_seconds: Option<u32>,
}

/// Response body returned by `POST .../credential-offers` on
/// success (HTTP 201).
///
/// `pre_auth_code` is the **bare** OID4VCI secret returned to the
/// caller exactly once; only its hash is persisted, so this is the
/// only opportunity to capture it. `offer_deeplink` is an
/// `openid-credential-offer://` URI suitable for rendering as a
/// QR code or handing to the holder's wallet.
#[derive(Debug, Serialize)]
pub struct CreateCredentialOfferResponse {
    pub id: String,
    pub pre_auth_code: String,
    pub offer_deeplink: String,
    pub expires_at: DateTime<Utc>,
}

/// Response body returned by
/// `GET .../credential-offers/{offer_id}` on success (HTTP 200).
///
/// `state` is the offer's *observed* state: when an offer is
/// still stored as `Pending` past its `expires_at`, this field is
/// `"expired"` even though the database row has not been updated.
/// Deliberately omits any pre-auth-code field — the bare secret
/// was returned only at creation, and the stored hash is not
/// surfaced.
#[derive(Debug, Serialize)]
pub struct GetCredentialOfferResponse {
    pub id: String,
    pub issuer_id: String,
    pub vct: String,
    pub claims: Value,
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Response body returned by
/// `GET .../credential-offers/{offer_id}/status` on success
/// (HTTP 200).
///
/// Lightweight projection for polling business applications: no
/// claims, no PII, no `vct`, no `created_at`. `state` is the
/// *observed* state, identical to the field surfaced by the full
/// fetch endpoint.
#[derive(Debug, Serialize)]
pub struct OfferStatusResponse {
    pub id: String,
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Query parameters for `GET .../credential-offers`.
///
/// All fields are optional. `limit` is bounded at the handler; out-of-range
/// values yield `invalid_input`. `cursor` is opaque to clients — the handler
/// rejects anything it did not itself emit. `state` filters on the
/// *observed* projection: `expired` matches stored-`pending` rows past their
/// `expires_at`, and `pending` matches stored-`pending` rows still within it.
#[derive(Debug, Deserialize)]
pub struct ListCredentialOffersQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListCredentialOffersResponse {
    pub items: Vec<GetCredentialOfferResponse>,
    pub next_cursor: Option<String>,
}
