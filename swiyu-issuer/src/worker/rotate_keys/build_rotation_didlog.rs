//! `build_rotation_didlog` step executor.
//!
//! Fetches the current DIDLog tail from the registry and constructs
//! the rotation entry locally to validate that every dependency
//! works (issuer is still `Active`, the registry is reachable, the
//! tail entry has the right shape, the new keys have the right
//! algorithms, the outgoing Authorized key is present and signs
//! cleanly). The entry itself is discarded — `publish_didlog`
//! re-derives it deterministically from the same inputs. The point
//! of this step is to fail fast before `publish_didlog` makes a second
//! registry round-trip.
//!
//! Error classification mirrors `build_deactivation_didlog`:
//! - retryable [`RegistryError`](swiyu_registries::common::RegistryError)
//!   from the tail fetch → `Retry`
//! - non-retryable [`RegistryError`](swiyu_registries::common::RegistryError)
//!   from the tail fetch → `Terminal`
//! - signing-engine backend error → `Retry`
//! - everything else → `Terminal`

use std::str::FromStr;

use chrono::{DateTime, Utc};

use swiyu_core::did::DID;

use crate::domain::{Issuer, SigningEngine, SigningEngineError, StepOutcome, StepResult};
use crate::worker::didlog_common::ChainedBuildError;
use crate::worker::registry_facades::RegistryFacade;

use super::didlog_builder::{BuildError, build_rotation_entry};
use super::state::RotateKeysStateData;

pub async fn execute_build_rotation_didlog<R: RegistryFacade, S: SigningEngine>(
    issuer: &Issuer,
    state: &RotateKeysStateData,
    registry: &R,
    engine: &S,
    now: DateTime<Utc>,
) -> StepOutcome {
    let new_triple = match state.new_key_triple.as_ref() {
        Some(t) => t,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing new_key_triple".into(),
            };
        }
    };

    let did = match DID::from_str(&issuer.did) {
        Ok(d) => d,
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: "invalid_issuer_did".into(),
                error_message: format!("cannot parse issuer did {}: {e}", issuer.did),
            };
        }
    };

    let log = match registry.fetch_log(&did).await {
        Ok(fetched) => fetched.entries,
        Err(e) if e.is_retryable() => {
            return StepOutcome::Retry {
                error_code: "registry_unavailable".into(),
                error_message: e.to_string(),
            };
        }
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: "registry_rejected".into(),
                error_message: e.to_string(),
            };
        }
    };

    match build_rotation_entry(issuer, new_triple, &log, engine, now).await {
        Ok(_entry) => StepOutcome::Done(StepResult::default()),
        Err(BuildError::Chained(ChainedBuildError::Engine(SigningEngineError::Backend(_)))) => {
            StepOutcome::Retry {
                error_code: "build_rotation_didlog_failed".into(),
                error_message: "signing-engine backend error".into(),
            }
        }
        Err(e) => StepOutcome::Terminal {
            error_code: e.error_code("build_rotation_didlog_failed").into(),
            error_message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use swiyu_core::didlog::{DIDLogEntry, LogEntryFormat};

    use crate::domain::signing_engine::test_support::{
        GetPublicKeyCall, MockSigningEngine, SignCall, fixture_p256_pk, fixture_signature,
    };
    use crate::domain::{Issuer, IssuerId, IssuerState, KeyAlgorithm, RawPublicKey, TenantId};
    use crate::worker::test_support::{
        FetchLogCall, MockRegistry, fixture_did, fixture_kid, fixture_now, fixture_p256,
        fixture_rotated_triple,
    };

    fn fixture_issuer() -> Issuer {
        Issuer {
            id: IssuerId::generate(),
            tenant_id: TenantId::generate(),
            did: fixture_did().into(),
            state: Some(IssuerState::Active),
            description: Some("fixture".into()),
            authorized_key_id: Some(fixture_kid(0x11)),
            authentication_key_id: Some(fixture_kid(0x22)),
            assertion_key_id: Some(fixture_kid(0x33)),
            display_name: Some("Fixture".into()),
            logo_uri: None,
            locale: None,
            created_at: Utc::now(),
        }
    }

    // Stand-in for the registry tail before the rotation we're about to publish:
    // the genesis entry's `updateKeys` references an "old" authorized multikey distinct from any new one.
    fn fixture_genesis_entry() -> DIDLogEntry {
        DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            "z6Mk-old-authorized",
            fixture_did(),
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T12:00:00Z",
        )
    }

    fn fixture_ed25519_pk(seed: u8) -> RawPublicKey {
        RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![seed; 32],
        }
    }

    /// Engine queue for a happy-path single-role rotation of
    /// authorized: the four `get_public_key` calls (new authorized,
    /// new authentication, new assertion, outgoing authorized for
    /// the proof's verification_method) plus the one `sign` call.
    fn engine_for_happy_path() -> MockSigningEngine {
        let engine = MockSigningEngine::new();
        // new authorized
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0xAA)));
        // new authentication
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        // new assertion
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        // outgoing authorized (for verification_method id)
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0x11)));
        // sign
        engine.enqueue_sign(SignCall::Ok(fixture_signature()));
        engine
    }

    #[tokio::test]
    async fn happy_path_returns_done_with_empty_patch() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = engine_for_happy_path();

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn signs_with_outgoing_authorized_when_authorized_is_rotated() {
        // Spec rule: the OLD authorized signs the rotation entry, even
        // when authorized is itself rotated.
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = engine_for_happy_path();

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        execute_build_rotation_didlog(&fixture_issuer(), &state, &registry, &engine, fixture_now())
            .await;

        let sign_calls = engine.sign_invocations.lock().unwrap();
        assert_eq!(sign_calls.len(), 1);
        let (signing_kid, _input) = &sign_calls[0];
        assert_eq!(
            *signing_kid,
            fixture_kid(0x11),
            "the OUTGOING authorized key must sign, not the new one",
        );
    }

    #[tokio::test]
    async fn missing_new_key_triple_is_terminal() {
        let registry = MockRegistry::new();
        // No fetch_log enqueued — should fail before touching the registry.
        let engine = MockSigningEngine::new();

        let state = RotateKeysStateData::default();
        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_state");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.fetch_log_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registry_5xx_is_retryable() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = MockSigningEngine::new();
        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };

        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "registry_unavailable");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn registry_404_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 404,
            body: "unknown identifier".into(),
        });
        let engine = MockSigningEngine::new();
        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };

        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "registry_rejected");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_log_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![]));
        let engine = MockSigningEngine::new();
        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };

        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "registry_empty_log");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn already_rotated_tail_is_terminal_in_build_step() {
        // Saga-resume short-circuit: registry tail's updateKeys[0]
        // already matches the new authorized's multikey. The build
        // step itself reports this as Terminal (the resume path is
        // expected to land in publish_didlog, not build_rotation_didlog).
        let registry = MockRegistry::new();

        // Genesis whose updateKeys[0] already matches the multikey
        // we'd compute from new_authorized's public key
        // (fixture_ed25519_pk(0xAA) → multikey of [0xAA; 32]).
        let new_authorized_multikey =
            swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey(&[0xAA; 32]);
        let already_rotated_genesis = DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            &new_authorized_multikey,
            fixture_did(),
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T12:00:00Z",
        );
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![already_rotated_genesis]));

        let engine = MockSigningEngine::new();
        // The check happens after fetching the three new public keys.
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0xAA)));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "already_rotated");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issuer_not_active_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.state = Some(IssuerState::Deactivated);

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        let outcome =
            execute_build_rotation_didlog(&issuer, &state, &registry, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "issuer_not_active");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_outgoing_authorized_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.authorized_key_id = None;

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        let outcome =
            execute_build_rotation_didlog(&issuer, &state, &registry, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_issuer_field");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_backend_error_is_retryable() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0xAA)));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0x11)));
        engine.enqueue_sign(SignCall::Backend("hsm offline".into()));

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "build_rotation_didlog_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_new_authorized_key_shape_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0; 31],
        }));

        let state = RotateKeysStateData {
            new_key_triple: Some(fixture_rotated_triple()),
            didlog_published: false,
        };
        let outcome = execute_build_rotation_didlog(
            &fixture_issuer(),
            &state,
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_public_key");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }
}
