//! Step 3 of the `CreateIssuer` saga: build the genesis DIDLog entry
//! locally so any failure surfaces *before* `publish_didlog` makes a
//! network round-trip.

use chrono::{DateTime, Utc};

use crate::domain::{SigningEngine, SigningEngineError, StepOutcome, StepResult};

use super::CreateIssuerStateData;
use super::didlog_builder::{BuildError, build_log_entry};

/// Constructs the entry deterministically from the inputs (key
/// triple, allocation URL, pinned `now`) and validates that every
/// dependency works: the key material is present and well-formed,
/// and the [`SigningEngine`] is responsive. The entry itself is
/// discarded — `publish_didlog` regenerates it from the same inputs,
/// producing byte-identical output.
pub async fn execute_build_initial_didlog<S: SigningEngine>(
    state: &CreateIssuerStateData,
    engine: &S,
    now: DateTime<Utc>,
) -> StepOutcome {
    match build_log_entry(state, engine, now).await {
        Ok(_entry) => StepOutcome::Done(StepResult::default()),
        Err(BuildError::Engine(SigningEngineError::Backend(_))) => StepOutcome::Retry {
            error_code: "build_initial_didlog_failed".into(),
            error_message: "signing-engine backend error".into(),
        },
        Err(e) => StepOutcome::Terminal {
            error_code: e.error_code("build_initial_didlog_failed").into(),
            error_message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::signing_engine::test_support::{
        GetPublicKeyCall, MockSigningEngine, SignCall, fixture_ed25519_pk, fixture_p256_pk,
    };
    use crate::domain::{KeyAlgorithm, RawPublicKey};
    use crate::worker::create_issuer::KeyTriple;
    use crate::worker::test_support::{fixture_kid, fixture_now};

    fn fixture_state() -> CreateIssuerStateData {
        CreateIssuerStateData {
            assigned_did_url: Some("https://reg.example.com/api/v1/did/abc/did.jsonl".into()),
            assigned_identifier: Some("abc".into()),
            key_ids: Some(KeyTriple {
                authorized: fixture_kid(0x11),
                authentication: fixture_kid(0x22),
                assertion: fixture_kid(0x33),
            }),
            didlog_published: false,
            status_list_registry_entry_id: None,
            status_list_registry_url: None,
        }
    }

    #[tokio::test]
    async fn happy_path_returns_done_with_empty_patch() {
        let engine = MockSigningEngine::for_happy_path();

        let outcome = execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        // Three get_public_key calls (one per role), one sign.
        assert_eq!(engine.public_key_invocations.lock().unwrap().len(), 3);
        assert_eq!(engine.sign_invocations.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn signs_64_byte_eddsa_jcs_2022_input() {
        // The eddsa-jcs-2022 cryptosuite hands Ed25519 a 64-byte
        // concatenation of two SHA-256 hashes. Verify the worker sends
        // the engine exactly that.
        let engine = MockSigningEngine::for_happy_path();

        execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        let (kid, input) = engine.sign_invocations.lock().unwrap()[0].clone();
        assert_eq!(kid, fixture_kid(0x11));
        assert_eq!(input.len(), 64, "eddsa-jcs-2022 input is 64 bytes");
    }

    #[tokio::test]
    async fn missing_assigned_did_url_is_terminal() {
        let engine = MockSigningEngine::new();
        let state = CreateIssuerStateData {
            assigned_did_url: None,
            key_ids: fixture_state().key_ids,
            ..CreateIssuerStateData::default()
        };

        let outcome = execute_build_initial_didlog(&state, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_state");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_key_ids_is_terminal() {
        let engine = MockSigningEngine::new();
        let state = CreateIssuerStateData {
            key_ids: None,
            ..fixture_state()
        };

        let outcome = execute_build_initial_didlog(&state, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_state");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_url_is_terminal() {
        let engine = MockSigningEngine::new();
        let state = CreateIssuerStateData {
            assigned_did_url: Some("ftp://bad.example/did.jsonl".into()),
            ..fixture_state()
        };

        let outcome = execute_build_initial_didlog(&state, &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_allocation_url");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn engine_backend_error_is_retryable() {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Backend("connection refused".into()));

        let outcome = execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "build_initial_didlog_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn engine_key_not_found_is_terminal() {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::NotFound(fixture_kid(0x11)));

        let outcome = execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "build_initial_didlog_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_backend_error_is_retryable() {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_sign(SignCall::Backend("hsm offline".into()));

        let outcome = execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "build_initial_didlog_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_key_not_found_is_terminal() {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_sign(SignCall::NotFound(fixture_kid(0x11)));

        let outcome = execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "build_initial_didlog_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_public_key_shape_is_terminal() {
        let engine = MockSigningEngine::new();
        // First call: a 31-byte "Ed25519" key (wrong length).
        engine.enqueue_public_key(GetPublicKeyCall::Ok(RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0; 31],
        }));

        let outcome = execute_build_initial_didlog(&fixture_state(), &engine, fixture_now()).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_public_key");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }
}
