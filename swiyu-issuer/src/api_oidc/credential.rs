use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::{
    AccessTokenSecret, CredentialOfferState, DomainError, INTEGRITY_HASH_LEN, IssuedCredential,
    IssuerId, KeyPairId, NonceSecret, SigningEngine, SigningEngineError, StatusListId,
    StatusListIndex,
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

/// How long an issued credential remains valid. v0.1.0 hard-codes one
/// year; a per-credential-type policy lands when credential-type
/// management does. The same value drives both the JWS `exp` claim
/// and the `issued_credentials.expires_at` column so the row mirrors
/// what the wallet holds.
const CREDENTIAL_VALIDITY_DAYS: i64 = 365;

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

/// `POST /i/{issuer_id}/credential`
///
/// OID4VCI credential-issuance endpoint. The wallet presents its bearer access token and a
/// wallet-proof JWT; if both are valid and the underlying offer is still pending, the issuer
/// signs and returns an SD-JWT VC.
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
    .map_err(OAuthError::from)?
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

    // The offer must be pending and unexpired; observed-state resolution
    // treats stored-pending past `expires_at` as Expired, which fails the check below.
    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &token.tenant_id,
        &token.issuer_id,
        &token.offer_id,
    )
    .await
    .map_err(OAuthError::from)?;

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
        .map_err(OAuthError::from)?
        .ok_or_else(|| {
            OAuthError::Internal(Box::new(std::io::Error::other(
                "issuer disappeared after access-token validation",
            )))
        })?;

    // The credential's JWS is signed with the issuer's Assertion key (P-256 / ES256).
    // An issuer without an Assertion key must be onboarded through the create_issuer
    // task flow on the management API before it can issue credentials.
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
    proof_claims.verify_signature()?;

    // Atomically consume the nonce. Returns the offer_id it was
    // bound to; that must match the access-token's offer or we
    // reject with `invalid_proof`.
    let nonce_secret = NonceSecret::from_stored(proof_claims.nonce);
    let nonce_offer_id =
        persistence::oidc::nonces::consume_by_hash(&mut conn, &nonce_secret.hash(), now)
            .await
            .map_err(OAuthError::from)?
            .ok_or_else(|| OAuthError::InvalidProof {
                description: "nonce is unknown, expired, or already consumed".to_string(),
            })?;
    if nonce_offer_id != offer.id {
        return Err(OAuthError::InvalidProof {
            description: "nonce was minted for a different offer".to_string(),
        });
    }

    // From here on, every state-changing step runs inside one
    // transaction: status-list allocate, sign, hash, insert
    // IssuedCredential, transition the offer, delete the access
    // token, COMMIT. ROLLBACK on any failure is all-or-nothing —
    // there is no path where the wallet sees a credential out the
    // door but the local trace (allocation, row, offer transition)
    // is half-applied.
    //
    // Signing latency (a few ms) extends the transaction; keep the connection
    // pool sized accordingly.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    // Re-read the offer under FOR UPDATE so the aggregate's
    // try_issue precondition is enforced under a row-level lock.
    // A concurrent cancel that happens between the pre-tx
    // observed-state check and this point waits on the lock; the
    // re-read then surfaces the new state and try_issue rejects.
    let mut offer = persistence::oidc::credential_offers::find_by_id_for_update(
        &mut tx,
        &token.tenant_id,
        &token.issuer_id,
        &token.offer_id,
    )
    .await
    .map_err(|err| match err {
        persistence::PersistenceError::NotFound => OAuthError::InvalidToken {
            description: "the offer is no longer redeemable".to_string(),
        },
        other => OAuthError::Internal(Box::new(std::io::Error::other(other.to_string()))),
    })?;
    offer.try_issue(now).map_err(|err| match err {
        DomainError::StateTransitionNotAllowed => OAuthError::InvalidToken {
            description: "the offer is no longer redeemable".to_string(),
        },
        other => OAuthError::Internal(Box::new(std::io::Error::other(other.to_string()))),
    })?;

    let (status_list_id, status_list_index, status_list_registry_url) =
        allocate_status_slot(&mut tx, &issuer.id).await?;

    let status_claim = build_status_claim(&status_list_registry_url, status_list_index);
    let expires_at = now + Duration::days(CREDENTIAL_VALIDITY_DAYS);
    let credential = build_sd_jwt_vc(
        state.signing_engine.as_ref(),
        &assertion_key_id,
        &issuer,
        &offer,
        &proof_claims.cnf_jwk,
        &status_claim,
        now,
        expires_at,
    )
    .await
    .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    let integrity_hash: [u8; INTEGRITY_HASH_LEN] = Sha256::digest(credential.as_bytes()).into();
    let issued_credential = IssuedCredential::new(
        token.tenant_id.clone(),
        issuer.id.clone(),
        offer.id.clone(),
        offer.vct.clone(),
        cnf_jwk_thumbprint(&proof_claims.cnf_jwk)?,
        status_list_id,
        status_list_index,
        integrity_hash,
        now,
        expires_at,
    );
    persistence::issued_credentials::insert(&mut tx, &issued_credential)
        .await
        .map_err(OAuthError::from)?;
    // TODO(audit): record IssuedCredentialIssued event in the same
    // transaction (action=issue, target=issued_credential.id, details
    // includes the originating offer_id).

    persistence::oidc::credential_offers::set_issued_state(&mut tx, &offer)
        .await
        .map_err(OAuthError::from)?;
    persistence::oidc::access_tokens::delete_by_hash(&mut tx, &token.token_hash)
        .await
        .map_err(OAuthError::from)?;
    tx.commit()
        .await
        .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    Ok(Json(CredentialResponse { credential }))
}

/// Resolves the issuer's current status list, returns its public
/// `registry_url`, and atomically allocates the next free index.
///
/// Refuses to issue when the issuer has no current list, when that
/// list lacks a `registry_url`, or when it is at capacity. The first
/// two cases mean the issuer has not been fully onboarded against the
/// SWIYU Status Registry; the third means the operator must roll over
/// to a new list out-of-band. None of these recover by lazy
/// in-handler provisioning, because a freshly minted list still
/// requires a registry round-trip to obtain its public URL — work
/// that belongs in the create_issuer worker, not in the issuance hot
/// path.
async fn allocate_status_slot(
    tx: &mut sqlx::PgConnection,
    issuer_id: &IssuerId,
) -> Result<(StatusListId, StatusListIndex, String), OAuthError> {
    let (list_id, registry_url) = match persistence::status_lists::current_for_issuer_with_url(
        tx, issuer_id,
    )
    .await
    .map_err(OAuthError::from)?
    {
        Some((id, Some(url))) => (id, url),
        Some((id, None)) => {
            return Err(OAuthError::Internal(Box::new(std::io::Error::other(
                format!(
                    "status list {id} for issuer {issuer_id} has no registry_url; \
                         create_issuer must complete the create_status_list_entry step before issuance"
                ),
            ))));
        }
        None => {
            return Err(OAuthError::Internal(Box::new(std::io::Error::other(
                format!(
                    "issuer {issuer_id} has no current status list; \
                         create_issuer must complete the provision_status_list step before issuance"
                ),
            ))));
        }
    };

    let index = persistence::status_lists::allocate_index(tx, &list_id)
        .await
        .map_err(OAuthError::from)?
        .ok_or_else(|| {
            OAuthError::Internal(Box::new(std::io::Error::other(format!(
                "status list {list_id} is at capacity; rollover to a fresh \
                 list requires a registry round-trip and is not performed in \
                 the issuance handler"
            ))))
        })?;

    Ok((list_id, index, registry_url))
}

/// Renders the SD-JWT VC `status` claim. Wire shape per W3C Bitstring
/// Status List + SD-JWT VC: a single `status_list` member carrying
/// `idx` and `uri`. The `uri` is the SWIYU Status Registry's public
/// URL for the list, captured at registry-allocation time and
/// persisted in `status_lists.registry_url`.
fn build_status_claim(registry_url: &str, index: StatusListIndex) -> Value {
    json!({
        "status_list": {
            "idx": index.value(),
            "uri": registry_url,
        }
    })
}

/// Computes the RFC 7638 JWK thumbprint for the wallet's `cnf` key,
/// base64url-encoded — the `holder_key_jkt` column on the
/// `issued_credentials` row. Falls back to a stable hash of the
/// canonicalised JWK shape when the key uses an unfamiliar `kty` so
/// that the column always carries *something* the audit log can
/// correlate against later. Both EdDSA (`OKP`) and ES256 (`EC`)
/// follow the canonical RFC 7638 member ordering.
fn cnf_jwk_thumbprint(cnf_jwk: &Value) -> Result<String, OAuthError> {
    let kty =
        cnf_jwk
            .get("kty")
            .and_then(Value::as_str)
            .ok_or_else(|| OAuthError::InvalidProof {
                description: "cnf JWK is missing `kty`".to_string(),
            })?;
    let canonical = match kty {
        "OKP" => {
            let crv = cnf_jwk.get("crv").and_then(Value::as_str).ok_or_else(|| {
                OAuthError::InvalidProof {
                    description: "OKP cnf JWK is missing `crv`".to_string(),
                }
            })?;
            let x = cnf_jwk.get("x").and_then(Value::as_str).ok_or_else(|| {
                OAuthError::InvalidProof {
                    description: "OKP cnf JWK is missing `x`".to_string(),
                }
            })?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        "EC" => {
            let crv = cnf_jwk.get("crv").and_then(Value::as_str).ok_or_else(|| {
                OAuthError::InvalidProof {
                    description: "EC cnf JWK is missing `crv`".to_string(),
                }
            })?;
            let x = cnf_jwk.get("x").and_then(Value::as_str).ok_or_else(|| {
                OAuthError::InvalidProof {
                    description: "EC cnf JWK is missing `x`".to_string(),
                }
            })?;
            let y = cnf_jwk.get("y").and_then(Value::as_str).ok_or_else(|| {
                OAuthError::InvalidProof {
                    description: "EC cnf JWK is missing `y`".to_string(),
                }
            })?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        other => {
            return Err(OAuthError::InvalidProof {
                description: format!("unsupported cnf JWK kty {other:?}"),
            });
        }
    };
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
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
    /// JWS `alg` from the proof header.
    /// [`verify_signature`][Self::verify_signature] dispatches on
    /// this; only `EdDSA` and `ES256` are accepted.
    alg: String,
    /// `<header_b64>.<payload_b64>` — the bytes the wallet signed.
    signing_input: String,
    /// Raw signature bytes (decoded from the JWT's third segment):
    /// 64 bytes for both EdDSA (Ed25519) and ES256 (raw R||S).
    signature: Vec<u8>,
}

/// Parses the wallet's proof JWT — structural validation only.
///
/// Validates the claims that are required to bind the credential to
/// the wallet at issuance time:
///
/// - JWT structure (three base64url-encoded segments).
/// - Header carries a `jwk` (the wallet's public key) and `alg`.
/// - Body has `aud` matching the issuer URL, `iat` within
///   [`PROOF_IAT_SKEW_SECONDS`] of `now`, and a `nonce`.
///
/// Cryptographic verification of the signature lives in
/// [`verify_signature`][ProofClaims::verify_signature]; the handler
/// calls both in sequence so "shape valid" and "cryptographically
/// valid" remain independently testable failure modes.
fn parse_wallet_proof(
    jwt: &str,
    issuer_base_url: &str,
    issuer_id: &IssuerId,
    now: chrono::DateTime<Utc>,
) -> Result<ProofClaims, OAuthError> {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().ok_or_else(invalid_proof_structure)?;
    let payload_b64 = parts.next().ok_or_else(invalid_proof_structure)?;
    let signature_b64 = parts.next().ok_or_else(invalid_proof_structure)?;
    if parts.next().is_some() {
        return Err(invalid_proof_structure());
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| invalid_proof_structure())?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| invalid_proof_structure())?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| invalid_proof_structure())?;

    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| invalid_proof_structure())?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid_proof_structure())?;

    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuthError::InvalidProof {
            description: "proof JWT header is missing `alg`".to_string(),
        })?
        .to_string();

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

    let signing_input = format!("{header_b64}.{payload_b64}");

    Ok(ProofClaims {
        nonce,
        cnf_jwk,
        alg,
        signing_input,
        signature,
    })
}

impl ProofClaims {
    /// Cryptographically verifies the wallet proof JWT's signature
    /// against the public key the proof's header carries (`jwk`).
    ///
    /// Without this the wallet's possession-of-key claim is
    /// unprovable: anyone holding the pre-auth code could mint a
    /// credential bound to a public key they do not control.
    /// Supports the two algorithms SD-JWT VC wallets actually use:
    ///
    /// - `ES256` — ECDSA over P-256 with SHA-256, IEEE-P1363 (raw
    ///   R||S) signature encoding (the JWS form).
    /// - `EdDSA` — Ed25519, 64-byte signature.
    ///
    /// All failure modes (unsupported alg, malformed jwk, signature
    /// mismatch) collapse to [`InvalidProof`][OAuthError::InvalidProof]
    /// with a description that names the failure.
    fn verify_signature(&self) -> Result<(), OAuthError> {
        // Reconstruct the JOSE header from the two fields the parser
        // extracted, then delegate to swiyu-core's JWS verifier — the
        // same primitive swiyu-didtool's verify-pop will eventually
        // share.
        let header = json!({
            "alg": self.alg.as_str(),
            "jwk": self.cnf_jwk.clone(),
        });
        swiyu_core::jws::verify_with_embedded_jwk(
            &header,
            self.signing_input.as_bytes(),
            &self.signature,
        )
        .map_err(|e| OAuthError::InvalidProof {
            description: e.to_string(),
        })
    }
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
/// via [`SigningEngine::sign`]. ES256 in JWS hashes the signing
/// input with SHA-256 and signs the digest; both
/// [`DevSigningEngine`][crate::domain::DevSigningEngine] and
/// [`VaultSigningEngine`][crate::domain::VaultSigningEngine] expect
/// the 32-byte prehash, so we compute it here.
///
/// Generic over the engine so unit tests can drive the function with
/// a [`MockSigningEngine`][crate::test_support::domain::signing_engine::MockSigningEngine];
/// production passes `&`[`AnySigningEngine`][crate::domain::AnySigningEngine].
#[allow(clippy::too_many_arguments)]
async fn build_sd_jwt_vc<S: SigningEngine>(
    engine: &S,
    assertion_key_id: &KeyPairId,
    issuer: &crate::domain::Issuer,
    offer: &crate::domain::CredentialOffer,
    cnf_jwk: &Value,
    status_claim: &Value,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
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
    payload.insert(
        "exp".to_string(),
        Value::Number(expires_at.timestamp().into()),
    );
    payload.insert("vct".to_string(), Value::String(offer.vct.clone()));
    payload.insert("cnf".to_string(), json!({ "jwk": cnf_jwk.clone() }));
    payload.insert("status".to_string(), status_claim.clone());
    // All claims are plaintext in the payload (degenerate SD-JWT —
    // no `_sd` array, no salted disclosures).
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_status_claim_uses_registry_url_verbatim() {
        let index = StatusListIndex::try_from(42u32).unwrap();
        let registry_url = "https://status-reg.example.com/api/v1/statuslist/abc-123-uuid.jwt";
        let claim = build_status_claim(registry_url, index);
        assert_eq!(claim["status_list"]["idx"], 42);
        assert_eq!(claim["status_list"]["uri"], registry_url);
    }

    #[test]
    fn cnf_jwk_thumbprint_for_ed25519_jwk() {
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        });
        // Reference vector from RFC 8037 § A.3 (the same key the RFC
        // uses for its sample thumbprint).
        let jkt = cnf_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(jkt, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn cnf_jwk_thumbprint_for_p256_jwk_is_stable_across_member_order() {
        // The canonical ordering documented in RFC 7638 is alphabetical:
        // crv, kty, x, y. Two JWKs that differ only in member order must
        // hash identically.
        let jwk_a = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "abc",
            "y": "def",
        });
        let jwk_b = json!({
            "y": "def",
            "x": "abc",
            "crv": "P-256",
            "kty": "EC",
        });
        assert_eq!(
            cnf_jwk_thumbprint(&jwk_a).unwrap(),
            cnf_jwk_thumbprint(&jwk_b).unwrap()
        );
    }

    #[test]
    fn cnf_jwk_thumbprint_rejects_unsupported_kty() {
        let jwk = json!({"kty": "RSA", "n": "…", "e": "AQAB"});
        assert!(matches!(
            cnf_jwk_thumbprint(&jwk),
            Err(OAuthError::InvalidProof { .. })
        ));
    }

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

    mod build_sd_jwt_vc_tests {
        use super::*;

        use chrono::Duration;

        use crate::domain::{
            CredentialOffer, Issuer, KeyAlgorithm, PreAuthCode, Signature, TenantId,
        };
        use crate::test_support::domain::signing_engine::{MockSigningEngine, SignCall};

        const FIXTURE_DID: &str =
            "did:tdw:scid-placeholder:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d";

        fn fixture_issuer(assertion_key_id: KeyPairId) -> Issuer {
            let mut issuer = crate::test_support::fixture_issuer();
            issuer.assertion_key_id = Some(assertion_key_id);
            issuer
        }

        fn fixture_offer(claims: Value) -> CredentialOffer {
            CredentialOffer::new(
                TenantId::generate(),
                IssuerId::generate(),
                "vc-fixture".into(),
                claims,
                PreAuthCode::generate(),
                Utc::now() + Duration::minutes(5),
            )
        }

        fn fixture_signature() -> Signature {
            // 64 bytes — the JWS body for ES256 is raw R||S, fixed length.
            Signature {
                algorithm: KeyAlgorithm::EcdsaP256,
                bytes: vec![0xAB; 64],
            }
        }

        fn fixture_status_claim() -> Value {
            json!({
                "status_list": {
                    "idx": 0u32,
                    "uri": "https://example.invalid/status_list_test",
                }
            })
        }

        fn fixture_expires_at(now: DateTime<Utc>) -> DateTime<Utc> {
            now + Duration::days(CREDENTIAL_VALIDITY_DAYS)
        }

        fn split_jws(credential: &str) -> (Value, Value, Vec<u8>) {
            assert!(credential.ends_with('~'), "SD-JWT VC ends with `~`");
            let core = credential.trim_end_matches('~');
            let parts: Vec<&str> = core.split('.').collect();
            assert_eq!(parts.len(), 3, "JWS has three segments");
            let header: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
            let payload: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            (header, payload, signature)
        }

        #[tokio::test]
        async fn header_is_es256_with_assertion_kid() {
            let engine = MockSigningEngine::new();
            engine.enqueue_sign(SignCall::Ok(fixture_signature()));
            let assertion_key_id = KeyPairId::generate();
            let issuer = fixture_issuer(assertion_key_id);
            let offer = fixture_offer(json!({}));
            let now = Utc::now();

            let credential = build_sd_jwt_vc(
                &engine,
                &assertion_key_id,
                &issuer,
                &offer,
                &json!({}),
                &fixture_status_claim(),
                now,
                fixture_expires_at(now),
            )
            .await
            .unwrap();

            let (header, _, _) = split_jws(&credential);
            assert_eq!(header["alg"], "ES256");
            assert_eq!(header["typ"], "vc+sd-jwt");
            assert_eq!(header["kid"], format!("{FIXTURE_DID}#assertion-key-01"));
        }

        #[tokio::test]
        async fn payload_carries_iss_vct_cnf_and_offer_claims() {
            let engine = MockSigningEngine::new();
            engine.enqueue_sign(SignCall::Ok(fixture_signature()));
            let assertion_key_id = KeyPairId::generate();
            let issuer = fixture_issuer(assertion_key_id);
            let offer = fixture_offer(json!({"name": "Alice", "age": 30}));
            let cnf_jwk = json!({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"});
            let now = Utc::now();
            let expires_at = fixture_expires_at(now);

            let credential = build_sd_jwt_vc(
                &engine,
                &assertion_key_id,
                &issuer,
                &offer,
                &cnf_jwk,
                &fixture_status_claim(),
                now,
                expires_at,
            )
            .await
            .unwrap();

            let (_, payload, _) = split_jws(&credential);
            assert_eq!(payload["iss"], FIXTURE_DID);
            assert_eq!(payload["vct"], "vc-fixture");
            assert_eq!(payload["iat"], now.timestamp());
            assert_eq!(payload["exp"], expires_at.timestamp());
            assert_eq!(payload["cnf"]["jwk"], cnf_jwk);
            assert_eq!(payload["name"], "Alice");
            assert_eq!(payload["age"], 30);
        }

        #[tokio::test]
        async fn payload_carries_status_claim() {
            let engine = MockSigningEngine::new();
            engine.enqueue_sign(SignCall::Ok(fixture_signature()));
            let assertion_key_id = KeyPairId::generate();
            let issuer = fixture_issuer(assertion_key_id);
            let offer = fixture_offer(json!({}));
            let now = Utc::now();
            let status_claim = json!({
                "status_list": {
                    "idx": 42,
                    "uri": "https://registry.example.com/sl/abc",
                }
            });

            let credential = build_sd_jwt_vc(
                &engine,
                &assertion_key_id,
                &issuer,
                &offer,
                &json!({}),
                &status_claim,
                now,
                fixture_expires_at(now),
            )
            .await
            .unwrap();

            let (_, payload, _) = split_jws(&credential);
            assert_eq!(payload["status"], status_claim);
        }

        #[tokio::test]
        async fn signature_segment_is_engine_bytes_base64url_encoded() {
            let engine = MockSigningEngine::new();
            engine.enqueue_sign(SignCall::Ok(fixture_signature()));
            let assertion_key_id = KeyPairId::generate();
            let issuer = fixture_issuer(assertion_key_id);
            let offer = fixture_offer(json!({}));
            let now = Utc::now();

            let credential = build_sd_jwt_vc(
                &engine,
                &assertion_key_id,
                &issuer,
                &offer,
                &json!({}),
                &fixture_status_claim(),
                now,
                fixture_expires_at(now),
            )
            .await
            .unwrap();

            let (_, _, signature_bytes) = split_jws(&credential);
            assert_eq!(signature_bytes, fixture_signature().bytes);
        }

        #[tokio::test]
        async fn engine_signs_sha256_prehash_of_header_dot_payload() {
            // ES256 in JWS = ECDSA over P-256 with SHA-256. Both
            // signing-engine backends require the caller to prehash;
            // verify we hand the engine the right 32 bytes.
            let engine = MockSigningEngine::new();
            engine.enqueue_sign(SignCall::Ok(fixture_signature()));
            let assertion_key_id = KeyPairId::generate();
            let issuer = fixture_issuer(assertion_key_id);
            let offer = fixture_offer(json!({}));
            let now = Utc::now();

            let credential = build_sd_jwt_vc(
                &engine,
                &assertion_key_id,
                &issuer,
                &offer,
                &json!({}),
                &fixture_status_claim(),
                now,
                fixture_expires_at(now),
            )
            .await
            .unwrap();

            let core = credential.trim_end_matches('~');
            let parts: Vec<&str> = core.split('.').collect();
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let expected_digest: Vec<u8> = Sha256::digest(signing_input.as_bytes()).to_vec();

            let recorded = engine.sign_invocations.lock().unwrap();
            assert_eq!(recorded.len(), 1);
            let (kid, input) = &recorded[0];
            assert_eq!(*kid, assertion_key_id);
            assert_eq!(input, &expected_digest);
        }

        #[tokio::test]
        async fn engine_backend_error_propagates() {
            let engine = MockSigningEngine::new();
            engine.enqueue_sign(SignCall::Backend("hsm offline".into()));
            let assertion_key_id = KeyPairId::generate();
            let issuer = fixture_issuer(assertion_key_id);
            let offer = fixture_offer(json!({}));
            let now = Utc::now();

            let err = build_sd_jwt_vc(
                &engine,
                &assertion_key_id,
                &issuer,
                &offer,
                &json!({}),
                &fixture_status_claim(),
                now,
                fixture_expires_at(now),
            )
            .await
            .unwrap_err();

            assert!(matches!(
                err,
                BuildError::Engine(SigningEngineError::Backend(_))
            ));
        }
    }

    mod verify_signature_tests {
        use super::*;

        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        use p256::ecdsa::SigningKey as EcdsaSigningKey;
        use p256::ecdsa::signature::Signer as _;
        use rand_core::OsRng;

        const SIGNING_INPUT: &str = "header_b64.payload_b64";

        fn ed25519_proof(signing_input: &str) -> ProofClaims {
            let signing_key = Ed25519SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let x_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
            let cnf_jwk = json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x_b64,
            });
            let signature = signing_key
                .sign(signing_input.as_bytes())
                .to_bytes()
                .to_vec();
            ProofClaims {
                nonce: "n".into(),
                cnf_jwk,
                alg: "EdDSA".into(),
                signing_input: signing_input.into(),
                signature,
            }
        }

        fn es256_proof(signing_input: &str) -> ProofClaims {
            let signing_key = EcdsaSigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let encoded = verifying_key.to_encoded_point(false);
            let pk_bytes = encoded.as_bytes();
            // SEC1 uncompressed: 0x04 || x(32) || y(32).
            let x_b64 = URL_SAFE_NO_PAD.encode(&pk_bytes[1..33]);
            let y_b64 = URL_SAFE_NO_PAD.encode(&pk_bytes[33..65]);
            let cnf_jwk = json!({
                "kty": "EC",
                "crv": "P-256",
                "x": x_b64,
                "y": y_b64,
            });
            let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
            ProofClaims {
                nonce: "n".into(),
                cnf_jwk,
                alg: "ES256".into(),
                signing_input: signing_input.into(),
                signature: signature.to_bytes().to_vec(),
            }
        }

        #[test]
        fn ed25519_happy_path_verifies() {
            let proof = ed25519_proof(SIGNING_INPUT);
            assert!(proof.verify_signature().is_ok());
        }

        #[test]
        fn es256_happy_path_verifies() {
            let proof = es256_proof(SIGNING_INPUT);
            assert!(proof.verify_signature().is_ok());
        }

        #[test]
        fn ed25519_rejects_signature_over_different_input() {
            let mut proof = ed25519_proof(SIGNING_INPUT);
            // Change the signing_input *after* signing — the signature
            // is still well-formed but no longer matches the bytes
            // verify_signature will hash.
            proof.signing_input = "tampered".into();
            assert!(matches!(
                proof.verify_signature(),
                Err(OAuthError::InvalidProof { .. })
            ));
        }

        #[test]
        fn es256_rejects_signature_over_different_input() {
            let mut proof = es256_proof(SIGNING_INPUT);
            proof.signing_input = "tampered".into();
            assert!(matches!(
                proof.verify_signature(),
                Err(OAuthError::InvalidProof { .. })
            ));
        }

        #[test]
        fn rejects_unsupported_alg() {
            let mut proof = ed25519_proof(SIGNING_INPUT);
            proof.alg = "RS256".into();
            let err = proof.verify_signature().unwrap_err();
            match err {
                OAuthError::InvalidProof { description } => {
                    assert!(description.contains("RS256"), "{description}");
                }
                other => panic!("expected InvalidProof, got {other:?}"),
            }
        }

        #[test]
        fn ed25519_rejects_jwk_with_wrong_kty() {
            let mut proof = ed25519_proof(SIGNING_INPUT);
            proof.cnf_jwk["kty"] = json!("EC");
            assert!(matches!(
                proof.verify_signature(),
                Err(OAuthError::InvalidProof { .. })
            ));
        }

        #[test]
        fn ed25519_rejects_missing_x() {
            let mut proof = ed25519_proof(SIGNING_INPUT);
            proof.cnf_jwk.as_object_mut().unwrap().remove("x");
            assert!(matches!(
                proof.verify_signature(),
                Err(OAuthError::InvalidProof { .. })
            ));
        }

        #[test]
        fn ed25519_rejects_signature_of_wrong_length() {
            let mut proof = ed25519_proof(SIGNING_INPUT);
            proof.signature.truncate(63);
            assert!(matches!(
                proof.verify_signature(),
                Err(OAuthError::InvalidProof { .. })
            ));
        }

        #[test]
        fn es256_rejects_jwk_with_wrong_crv() {
            let mut proof = es256_proof(SIGNING_INPUT);
            proof.cnf_jwk["crv"] = json!("P-384");
            assert!(matches!(
                proof.verify_signature(),
                Err(OAuthError::InvalidProof { .. })
            ));
        }
    }
}
