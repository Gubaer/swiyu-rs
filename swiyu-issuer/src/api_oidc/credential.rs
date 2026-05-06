use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::{
    AccessTokenSecret, AnySigningEngine, CredentialOfferState, IssuerId, KeyPairId, NonceSecret,
    SigningEngine, SigningEngineError,
};
use crate::persistence;

use super::AppState;
use super::oauth_error::OAuthError;

const SUPPORTED_FORMAT: &str = "vc+sd-jwt";
const SUPPORTED_PROOF_TYPE: &str = "jwt";

/// Tolerance applied to the wallet proof's `iat` claim. Five minutes
/// matches the access-token TTL default and is also what the SWIYU
/// integration registry uses elsewhere.
const PROOF_IAT_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Deserialize)]
pub struct CredentialRequest {
    pub format: String,
    pub vct: String,
    pub proof: WalletProof,
}

#[derive(Debug, Deserialize)]
pub struct WalletProof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub credential: String,
}

pub async fn credential(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CredentialRequest>,
) -> Result<Json<CredentialResponse>, OAuthError> {
    tracing::debug!(
        issuer_id = %issuer_id_str,
        format = %payload.format,
        vct = %payload.vct,
        "credential request",
    );

    if payload.format != SUPPORTED_FORMAT {
        return Err(OAuthError::UnsupportedCredentialFormat {
            format: payload.format,
        });
    }
    if payload.proof.proof_type != SUPPORTED_PROOF_TYPE {
        return Err(OAuthError::InvalidProof {
            description: format!(
                "proof_type {:?} is not supported; only {:?}",
                payload.proof.proof_type, SUPPORTED_PROOF_TYPE
            ),
        });
    }

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
    let access_token_hash = extract_bearer_hash(&headers)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    let token = persistence::oidc::access_tokens::find_valid_by_hash(
        &mut conn,
        &access_token_hash,
        Utc::now(),
    )
    .await
    .map_err(map_lookup)?
    .ok_or_else(|| OAuthError::InvalidToken {
        description: "no valid access token matches the presented bearer".to_string(),
    })?;

    // Defense in depth: the access token was minted under a specific
    // issuer; if the path's issuer doesn't match, treat it as a bad
    // token rather than leaking which-token-where information.
    if token.issuer_id != issuer_id {
        return Err(OAuthError::InvalidToken {
            description: "access token does not authorise this issuer".to_string(),
        });
    }

    // Load the offer the access token was minted for. Per the spec,
    // the offer must be `pending` and unexpired; observed-state
    // resolution treats stored-`pending` past `expires_at` as
    // `Expired`, which fails the check.
    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &token.tenant_id,
        &token.issuer_id,
        &token.offer_id,
    )
    .await
    .map_err(map_lookup)?;

    let now = Utc::now();
    if offer.observed_state(now) != CredentialOfferState::Pending {
        return Err(OAuthError::InvalidToken {
            description: "the offer is no longer redeemable".to_string(),
        });
    }
    if payload.vct != offer.vct {
        return Err(OAuthError::InvalidCredentialRequest {
            description: format!("vct {:?} does not match the offer", payload.vct),
        });
    }

    let issuer = persistence::issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .map_err(map_lookup)?
        .ok_or_else(|| {
            OAuthError::Internal(Box::new(std::io::Error::other(
                "issuer disappeared after access-token validation",
            )))
        })?;

    // The credential's JWS is signed with the issuer's Assertion key
    // (P-256 / ES256). The seeded fixture issuer from migration 0001
    // has no Assertion key configured, so it cannot issue credentials
    // until it has been re-onboarded through the create_issuer task
    // flow on the management API.
    let assertion_key_id = issuer.assertion_key_id.ok_or_else(|| OAuthError::InvalidRequest {
        description: "issuer has no Assertion key configured; create the issuer through the issuer-management API first"
            .to_string(),
    })?;

    let proof_claims = parse_wallet_proof(
        &payload.proof.jwt,
        &state.config.issuer_base_url,
        &issuer_id,
        now,
    )?;

    // Atomically consume the nonce. Returns the offer_id it was
    // bound to; that must match the access-token's offer or we
    // reject with `invalid_proof`.
    let nonce_secret = NonceSecret::from_stored(proof_claims.nonce);
    let nonce_offer_id =
        persistence::oidc::nonces::consume_by_hash(&mut conn, &nonce_secret.hash(), now)
            .await
            .map_err(map_lookup)?
            .ok_or_else(|| OAuthError::InvalidProof {
                description: "nonce is unknown, expired, or already consumed".to_string(),
            })?;
    if nonce_offer_id != offer.id {
        return Err(OAuthError::InvalidProof {
            description: "nonce was minted for a different offer".to_string(),
        });
    }

    let credential = build_sd_jwt_vc(
        state.engine.as_ref(),
        &assertion_key_id,
        &issuer,
        &offer,
        &proof_claims.cnf_jwk,
        now,
    )
    .await
    .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    // Same-tx mark_issued + access-token deletion. A panic between
    // the two leaves either both or neither — there is no path that
    // ends with a credential out the door but the access token still
    // valid.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| OAuthError::Internal(Box::new(err)))?;
    persistence::oidc::credential_offers::mark_issued(
        &mut tx,
        &token.tenant_id,
        &token.issuer_id,
        &token.offer_id,
        now,
    )
    .await
    .map_err(|err| {
        // mark_issued returns NotFound on stale-state-during-update.
        // That maps to invalid_token because the offer was cancelled
        // (or otherwise transitioned out from under the wallet).
        match err {
            persistence::PersistenceError::NotFound => OAuthError::InvalidToken {
                description: "the offer is no longer redeemable".to_string(),
            },
            other => OAuthError::Internal(Box::new(std::io::Error::other(other.to_string()))),
        }
    })?;
    persistence::oidc::access_tokens::delete_by_hash(&mut tx, &token.token_hash)
        .await
        .map_err(map_lookup)?;
    tx.commit()
        .await
        .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    Ok(Json(CredentialResponse { credential }))
}

fn parse_issuer_id(raw: &str) -> Result<IssuerId, OAuthError> {
    IssuerId::from_bare(raw).map_err(|err| OAuthError::InvalidRequest {
        description: format!("issuer_id path parameter: {err}"),
    })
}

/// Pulls the bare access token out of `Authorization: Bearer …` and
/// hashes it for DB lookup. Generic 401 on every parse failure.
fn extract_bearer_hash(headers: &HeaderMap) -> Result<crate::domain::AccessTokenHash, OAuthError> {
    let raw = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| OAuthError::InvalidToken {
            description: "missing Authorization header".to_string(),
        })?
        .to_str()
        .map_err(|_| OAuthError::InvalidToken {
            description: "Authorization header is not valid UTF-8".to_string(),
        })?;
    let token = raw
        .strip_prefix("Bearer ")
        .ok_or_else(|| OAuthError::InvalidToken {
            description: "Authorization header is not a Bearer credential".to_string(),
        })?;
    if token.is_empty() {
        return Err(OAuthError::InvalidToken {
            description: "empty bearer credential".to_string(),
        });
    }
    Ok(AccessTokenSecret::from_stored(token).hash())
}

#[derive(Debug)]
struct ProofClaims {
    nonce: String,
    /// The wallet's public key (`jwk` member of the proof JWT
    /// header). Embedded as `cnf.jwk` in the issued credential.
    cnf_jwk: Value,
}

/// Parses the wallet's proof JWT.
///
/// **Does NOT verify the JWT signature** at v0.1.x — see
/// `impl_api_oidc.md` for the deferred slice that wires up real
/// JWS verification. Validates only the claims that are required
/// to bind the credential to the wallet at issuance time:
///
/// - JWT structure (three base64url-encoded segments).
/// - Header carries a `jwk` (the wallet's public key) and `alg`.
/// - Body has `aud` matching the issuer URL, `iat` within
///   `PROOF_IAT_SKEW_SECONDS` of `now`, and a `nonce`.
fn parse_wallet_proof(
    jwt: &str,
    issuer_base_url: &str,
    issuer_id: &IssuerId,
    now: chrono::DateTime<Utc>,
) -> Result<ProofClaims, OAuthError> {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().ok_or_else(invalid_proof_structure)?;
    let payload_b64 = parts.next().ok_or_else(invalid_proof_structure)?;
    let _signature_b64 = parts.next().ok_or_else(invalid_proof_structure)?;
    if parts.next().is_some() {
        return Err(invalid_proof_structure());
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| invalid_proof_structure())?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| invalid_proof_structure())?;

    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| invalid_proof_structure())?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid_proof_structure())?;

    let cnf_jwk = header
        .get("jwk")
        .cloned()
        .ok_or_else(|| OAuthError::InvalidProof {
            description: "proof JWT header is missing the `jwk` member".to_string(),
        })?;

    let expected_audience = format!(
        "{}/i/{}",
        issuer_base_url.trim_end_matches('/'),
        issuer_id.bare()
    );
    let aud =
        payload
            .get("aud")
            .and_then(Value::as_str)
            .ok_or_else(|| OAuthError::InvalidProof {
                description: "proof JWT payload is missing `aud`".to_string(),
            })?;
    if aud != expected_audience {
        return Err(OAuthError::InvalidProof {
            description: format!(
                "proof `aud` {aud:?} does not match issuer URL {expected_audience:?}"
            ),
        });
    }

    let iat =
        payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| OAuthError::InvalidProof {
                description: "proof JWT payload is missing `iat`".to_string(),
            })?;
    let now_ts = now.timestamp();
    if (iat - now_ts).abs() > PROOF_IAT_SKEW_SECONDS {
        return Err(OAuthError::InvalidProof {
            description: format!(
                "proof `iat` {iat} is more than {PROOF_IAT_SKEW_SECONDS}s away from server time"
            ),
        });
    }

    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuthError::InvalidProof {
            description: "proof JWT payload is missing `nonce`".to_string(),
        })?
        .to_string();

    Ok(ProofClaims { nonce, cnf_jwk })
}

fn invalid_proof_structure() -> OAuthError {
    OAuthError::InvalidProof {
        description: "proof JWT is malformed or not a three-segment JWS".to_string(),
    }
}

/// Builds a degenerate SD-JWT VC: a JWS whose payload carries every
/// claim plaintext (no `_sd`, no disclosures), terminated by a
/// trailing tilde so the format is wire-shape compatible with the
/// SD-JWT VC spec.
///
/// Real selective disclosure lands in a follow-up slice once a
/// per-credential-type policy on which claims are disclosable
/// exists.
///
/// The JWS is signed with the issuer's Assertion key (P-256 / ES256)
/// via [`AnySigningEngine::sign`]. ES256 in JWS hashes the signing
/// input with SHA-256 and signs the digest; both DevSigningEngine
/// and VaultSigningEngine expect the 32-byte prehash, so we compute
/// it here.
async fn build_sd_jwt_vc(
    engine: &AnySigningEngine,
    assertion_key_id: &KeyPairId,
    issuer: &crate::domain::Issuer,
    offer: &crate::domain::CredentialOffer,
    cnf_jwk: &Value,
    now: chrono::DateTime<Utc>,
) -> Result<String, BuildError> {
    // `kid` matches the verification-method id the create_issuer
    // worker writes into the published DID document
    // (`{did}#assertion-key-01` — see `swiyu_core::diddoc::DIDDoc::new_genesis`).
    let header = json!({
        "alg": "ES256",
        "typ": "vc+sd-jwt",
        "kid": format!("{}#assertion-key-01", issuer.did),
    });

    let mut payload = Map::new();
    payload.insert("iss".to_string(), Value::String(issuer.did.clone()));
    payload.insert("iat".to_string(), Value::Number(now.timestamp().into()));
    payload.insert("vct".to_string(), Value::String(offer.vct.clone()));
    payload.insert("cnf".to_string(), json!({ "jwk": cnf_jwk.clone() }));
    // All claims are plaintext in the payload (degenerate SD-JWT —
    // no `_sd` array, no salted disclosures). Document this trade-
    // off in `impl_api_oidc.md`.
    if let Value::Object(claims) = &offer.claims {
        for (k, v) in claims {
            payload.insert(k.clone(), v.clone());
        }
    }
    let payload = Value::Object(payload);

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = Sha256::digest(signing_input.as_bytes());
    let signature = engine.sign(assertion_key_id, &digest).await?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature.bytes);

    // Trailing `~` separator with zero disclosures — minimum
    // spec-conformant SD-JWT VC.
    Ok(format!("{header_b64}.{payload_b64}.{signature_b64}~"))
}

#[derive(Debug, Error)]
enum BuildError {
    #[error("JSON serialisation: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signing engine: {0}")]
    Engine(#[from] SigningEngineError),
}

fn map_lookup(err: persistence::PersistenceError) -> OAuthError {
    OAuthError::from(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build_proof_jwt(payload: Value) -> String {
        // Constructs a JWT-shaped string with a dummy signature
        // segment (the parser ignores it).
        let header = json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "abc" }
        });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let s = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{h}.{p}.{s}")
    }

    #[test]
    fn parse_wallet_proof_accepts_well_formed_jwt() {
        let issuer_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let now = Utc::now();
        let payload = json!({
            "aud": "https://issuer.example.com/i/9hXq2vRtL8pK7f",
            "iat": now.timestamp(),
            "nonce": "MyNonce123",
        });
        let jwt = build_proof_jwt(payload);
        let claims =
            parse_wallet_proof(&jwt, "https://issuer.example.com", &issuer_id, now).unwrap();
        assert_eq!(claims.nonce, "MyNonce123");
        assert_eq!(claims.cnf_jwk["kty"], "OKP");
    }

    #[test]
    fn parse_wallet_proof_rejects_wrong_audience() {
        let issuer_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let now = Utc::now();
        let payload = json!({
            "aud": "https://attacker.example.com/i/9hXq2vRtL8pK7f",
            "iat": now.timestamp(),
            "nonce": "MyNonce123",
        });
        let jwt = build_proof_jwt(payload);
        let err =
            parse_wallet_proof(&jwt, "https://issuer.example.com", &issuer_id, now).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidProof { .. }));
    }

    #[test]
    fn parse_wallet_proof_rejects_stale_iat() {
        let issuer_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let now = Utc::now();
        let payload = json!({
            "aud": "https://issuer.example.com/i/9hXq2vRtL8pK7f",
            "iat": now.timestamp() - 3600,
            "nonce": "MyNonce123",
        });
        let jwt = build_proof_jwt(payload);
        assert!(matches!(
            parse_wallet_proof(&jwt, "https://issuer.example.com", &issuer_id, now).unwrap_err(),
            OAuthError::InvalidProof { .. }
        ));
    }

    #[test]
    fn parse_wallet_proof_rejects_malformed_jwt() {
        let issuer_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let now = Utc::now();
        assert!(matches!(
            parse_wallet_proof("not.a.jwt.really", "https://x", &issuer_id, now).unwrap_err(),
            OAuthError::InvalidProof { .. }
        ));
        assert!(matches!(
            parse_wallet_proof("only-one-segment", "https://x", &issuer_id, now).unwrap_err(),
            OAuthError::InvalidProof { .. }
        ));
    }

    #[test]
    fn parse_wallet_proof_rejects_missing_jwk() {
        let issuer_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let now = Utc::now();
        let header = json!({ "alg": "EdDSA", "typ": "openid4vci-proof+jwt" });
        let payload = json!({
            "aud": "https://issuer.example.com/i/9hXq2vRtL8pK7f",
            "iat": now.timestamp(),
            "nonce": "n",
        });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let s = URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{h}.{p}.{s}");
        assert!(matches!(
            parse_wallet_proof(&jwt, "https://issuer.example.com", &issuer_id, now).unwrap_err(),
            OAuthError::InvalidProof { .. }
        ));
    }
}
