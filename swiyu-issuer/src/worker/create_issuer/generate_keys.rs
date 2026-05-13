//! Step 2 of the `CreateIssuer` saga: generate the three keypairs
//! (Authorized, Authentication, Assertion) the DID Document
//! references.

use serde_json::{Map, json};

use crate::domain::{KeyRole, SigningEngine, SigningEngineError, StepOutcome, StepResult};

use super::{CreateIssuerStateData, KeyTriple};

/// Calls the [`SigningEngine`] three times and records the resulting
/// [`KeyTriple`] in `state_data` so subsequent steps can sign with
/// the private keys and embed the public keys in the DID Document.
/// On saga resume this step short-circuits when `state_data.key_ids`
/// is already set, returning [`StepOutcome::Done`] with no further
/// engine calls.
///
/// A partial run leaves earlier-generated private keys inside the
/// engine; on retry the executor generates a fresh triple and the
/// orphans are cleaned up by a future periodic job rather than at
/// retry time.
pub async fn execute_generate_keys<S: SigningEngine>(
    state: &CreateIssuerStateData,
    engine: &S,
) -> StepOutcome {
    if state.key_ids.is_some() {
        return StepOutcome::Done(StepResult::default());
    }

    let authorized = match engine.generate_keypair(KeyRole::Authorized).await {
        Ok(kp) => kp.id,
        Err(e) => return outcome_for_engine_error("generate_keypair_failed", e),
    };
    let authentication = match engine.generate_keypair(KeyRole::Authentication).await {
        Ok(kp) => kp.id,
        Err(e) => return outcome_for_engine_error("generate_keypair_failed", e),
    };
    let assertion = match engine.generate_keypair(KeyRole::Assertion).await {
        Ok(kp) => kp.id,
        Err(e) => return outcome_for_engine_error("generate_keypair_failed", e),
    };

    let triple = KeyTriple {
        authorized,
        authentication,
        assertion,
    };
    let mut patch = Map::new();
    patch.insert("key_ids".into(), json!(triple));
    StepOutcome::Done(StepResult {
        state_data_patch: patch,
    })
}

fn outcome_for_engine_error(error_code: &str, e: SigningEngineError) -> StepOutcome {
    let error_message = e.to_string();
    match e {
        // Backend errors are most often transient (DB blip, vault hiccup).
        SigningEngineError::Backend(_) => StepOutcome::Retry {
            error_code: error_code.into(),
            error_message,
        },
        // The remaining variants signal a configuration or input bug;
        // retrying will not help.
        SigningEngineError::UnsupportedAlgorithm
        | SigningEngineError::InvalidInputLength { .. }
        | SigningEngineError::KeyNotFound(_) => StepOutcome::Terminal {
            error_code: error_code.into(),
            error_message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::signing_engine::test_support::{GenerateKeypairCall, MockSigningEngine};
    use crate::domain::{KeyAlgorithm, KeyPairId};
    use crate::worker::test_support::fixture_keypair;

    #[tokio::test]
    async fn happy_path_generates_three_keys_in_order() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
            0x11,
            KeyAlgorithm::Ed25519,
            32,
        )));
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
            0x22,
            KeyAlgorithm::EcdsaP256,
            65,
        )));
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
            0x33,
            KeyAlgorithm::EcdsaP256,
            65,
        )));

        let outcome = execute_generate_keys(&CreateIssuerStateData::default(), &engine).await;

        match outcome {
            StepOutcome::Done(result) => {
                let key_ids = &result.state_data_patch["key_ids"];
                assert!(key_ids.is_object(), "key_ids should be an object");
                assert!(key_ids["authorized"].is_string());
                assert!(key_ids["authentication"].is_string());
                assert!(key_ids["assertion"].is_string());
            }
            other => panic!("expected Done, got {other:?}"),
        }
        assert_eq!(
            engine.generate_invocations.lock().unwrap().as_slice(),
            &[
                KeyRole::Authorized,
                KeyRole::Authentication,
                KeyRole::Assertion
            ],
        );
    }

    #[tokio::test]
    async fn skips_when_key_ids_already_set() {
        let engine = MockSigningEngine::new();
        // Deliberately enqueue nothing — a call would panic.
        let triple = KeyTriple {
            authorized: KeyPairId::generate(),
            authentication: KeyPairId::generate(),
            assertion: KeyPairId::generate(),
        };
        let state = CreateIssuerStateData {
            key_ids: Some(triple),
            ..CreateIssuerStateData::default()
        };

        let outcome = execute_generate_keys(&state, &engine).await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(engine.generate_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn backend_error_on_first_call_is_retryable() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Backend("connection refused".into()));

        let outcome = execute_generate_keys(&CreateIssuerStateData::default(), &engine).await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "generate_keypair_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
        assert_eq!(engine.generate_invocations.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn backend_error_on_second_call_is_retryable() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
            0x11,
            KeyAlgorithm::Ed25519,
            32,
        )));
        engine.enqueue_generate(GenerateKeypairCall::Backend("transient".into()));

        let outcome = execute_generate_keys(&CreateIssuerStateData::default(), &engine).await;

        match outcome {
            StepOutcome::Retry { .. } => {}
            other => panic!("expected Retry, got {other:?}"),
        }
        assert_eq!(engine.generate_invocations.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn unsupported_algorithm_is_terminal() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Unsupported);

        let outcome = execute_generate_keys(&CreateIssuerStateData::default(), &engine).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "generate_keypair_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }
}
