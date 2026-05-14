//! `build_deactivation_didlog` step executor.
//!
//! Fetches the current DIDLog tail from the registry and constructs
//! the deactivation entry locally to validate that every dependency
//! works (issuer is still `Active`, the registry is reachable, the
//! tail entry has the right shape, the Authorized key is present and
//! signs cleanly). The entry itself is discarded — `publish_didlog`
//! re-derives it deterministically from the same inputs. The point
//! of this step is to fail fast before `publish_didlog` makes a second
//! registry round-trip.
//!
//! Error classification:
//! - retryable [`RegistryError`](swiyu_registries::common::RegistryError)
//!   from the tail fetch → `Retry` (registry transport flakiness on
//!   the read should not kill the saga)
//! - non-retryable [`RegistryError`](swiyu_registries::common::RegistryError)
//!   from the tail fetch → `Terminal`
//! - signing-engine backend error → `Retry`
//! - everything else (issuer state, missing fields, malformed
//!   predecessor entry, missing key, sign key-not-found) → `Terminal`

use std::str::FromStr;

use chrono::{DateTime, Utc};

use swiyu_core::did::DID;

use crate::domain::{Issuer, SigningEngine, SigningEngineError, StepOutcome, StepResult};
use crate::worker::didlog_common::ChainedBuildError;
use crate::worker::registry_facades::RegistryFacade;

use super::didlog_builder::{BuildError, build_deactivation_entry};

pub async fn execute_build_deactivation_didlog<R: RegistryFacade, S: SigningEngine>(
    issuer: &Issuer,
    registry: &R,
    engine: &S,
    now: DateTime<Utc>,
) -> StepOutcome {
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

    match build_deactivation_entry(issuer, &log, engine, now).await {
        Ok(_entry) => StepOutcome::Done(StepResult::default()),
        Err(BuildError::Chained(ChainedBuildError::Engine(SigningEngineError::Backend(_)))) => {
            StepOutcome::Retry {
                error_code: "build_deactivation_didlog_failed".into(),
                error_message: "signing-engine backend error".into(),
            }
        }
        Err(e) => StepOutcome::Terminal {
            error_code: e.error_code("build_deactivation_didlog_failed").into(),
            error_message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;

    use swiyu_core::diddoc::DIDDoc;
    use swiyu_core::didlog::{DIDLogEntry, LogEntryFormat};

    use crate::domain::signing_engine::test_support::{
        GetPublicKeyCall, MockSigningEngine, SignCall, fixture_ed25519_pk,
    };
    use crate::domain::{IssuerState, KeyAlgorithm, RawPublicKey};
    use crate::test_support::worker::{
        FetchLogCall, MockRegistry, fixture_did, fixture_issuer, fixture_kid, fixture_now,
        fixture_p256,
    };

    fn fixture_genesis_entry() -> DIDLogEntry {
        // A genesis entry whose did_doc_state is `Value` and whose
        // parameters do not carry `deactivated: true`. Stand-in for
        // the registry tail when the issuer is still active.
        DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            "z6Mk-authorized-fixture",
            fixture_did(),
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T12:00:00Z",
        )
    }

    #[tokio::test]
    async fn happy_path_returns_done_with_empty_patch() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::for_deactivation_happy_path();

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert_eq!(
            registry.fetch_log_invocations.lock().unwrap().as_slice(),
            &[DID::from_str(fixture_did()).unwrap()],
        );
    }

    #[tokio::test]
    async fn registry_5xx_is_retryable() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = MockSigningEngine::new();

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
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

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "registry_rejected");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn registry_decode_error_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Decode("malformed jsonl".into()));
        let engine = MockSigningEngine::new();

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
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

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "registry_empty_log");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn already_deactivated_tail_is_terminal() {
        let registry = MockRegistry::new();
        let prev_doc = DIDDoc::new_genesis(fixture_did(), &fixture_p256(), &fixture_p256());
        let already = DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrev",
            &prev_doc,
            "2026-05-04T13:00:00Z",
        );
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry(), already]));
        let engine = MockSigningEngine::new();

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "already_deactivated");
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

        let outcome =
            execute_build_deactivation_didlog(&issuer, &registry, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "issuer_not_active");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_authorized_key_id_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.authorized_key_id = None;

        let outcome =
            execute_build_deactivation_didlog(&issuer, &registry, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_issuer_field");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unparseable_did_is_terminal() {
        let registry = MockRegistry::new();
        // No fetch_log enqueued: the function should fail before
        // touching the registry, since the DID can't be parsed.
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.did = "not a did".into();

        let outcome =
            execute_build_deactivation_didlog(&issuer, &registry, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_issuer_did");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.fetch_log_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sign_backend_error_is_retryable() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_sign(SignCall::Backend("hsm offline".into()));

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "build_deactivation_didlog_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_key_not_found_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_sign(SignCall::NotFound(fixture_kid(0x11)));

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "build_deactivation_didlog_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_authorized_key_shape_is_terminal() {
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0; 31],
        }));

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_public_key");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn predecessor_state_is_patch_terminal() {
        // Hand-build a patch-state entry by parsing one from JSON;
        // there is no public constructor for `Patch`-state entries
        // in swiyu-core. The smallest legal did:tdw 0.3 entry is a
        // 5-element array.
        let json: Value = serde_json::json!([
            "1-QmPrev",
            "2026-05-04T12:00:00Z",
            { "method": "did:tdw:0.3", "scid": "abc", "updateKeys": ["z6Mk-x"] },
            { "patch": [] },
            [],
        ]);
        let entry = DIDLogEntry::try_from(&json).unwrap();

        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![entry]));
        let engine = MockSigningEngine::new();

        let outcome =
            execute_build_deactivation_didlog(&fixture_issuer(), &registry, &engine, fixture_now())
                .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "predecessor_state_is_patch");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }
}
