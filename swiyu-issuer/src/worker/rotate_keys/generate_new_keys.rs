//! `generate_new_keys` step executor for `RotateKeys`.
//!
//! For each role in `input.roles`, asks the SigningEngine for a
//! fresh key pair and slots its `KeyPairId` into the new triple.
//! Non-rotated roles carry the issuer's current ids forward
//! unchanged. The triple is recorded in `state_data.new_key_triple`
//! so a crash between this step and `build_rotation_log` does not
//! strand the freshly generated keys: a re-run sees the populated
//! field and short-circuits.
//!
//! As with `create_issuer::generate_keys`, a partial run can leave
//! orphan private keys inside the engine; cleanup is deferred to a
//! periodic job rather than handled at retry time.

use serde_json::{Map, json};

use crate::domain::{Issuer, KeyRole, SigningEngine, SigningEngineError, StepOutcome, StepResult};
use crate::worker::create_issuer::KeyTriple;

use super::{RotateKeysInput, RotateKeysStateData};

pub async fn execute_generate_new_keys<S: SigningEngine>(
    issuer: &Issuer,
    input: &RotateKeysInput,
    state: &RotateKeysStateData,
    engine: &S,
) -> StepOutcome {
    if state.new_key_triple.is_some() {
        return StepOutcome::Done(StepResult::default());
    }

    // Validate that every role NOT being rotated has a current key
    // on the issuer row. Rotating a malformed issuer (e.g. the
    // legacy seeded fixture with `state IS NULL` and no key ids)
    // would dereference a `None` here.
    for role in [
        KeyRole::Authorized,
        KeyRole::Authentication,
        KeyRole::Assertion,
    ] {
        if !input.roles.contains(&role) && issuer.key_id_for_role(role).is_none() {
            return StepOutcome::Terminal {
                error_code: "missing_issuer_field".into(),
                error_message: format!(
                    "issuer is missing current key for non-rotated role {role:?}"
                ),
            };
        }
    }

    let mut authorized = issuer.authorized_key_id;
    let mut authentication = issuer.authentication_key_id;
    let mut assertion = issuer.assertion_key_id;

    for role in &input.roles {
        let new_id = match engine.generate_keypair(*role).await {
            Ok(kp) => kp.id,
            Err(e) => return outcome_for_engine_error("generate_keypair_failed", e),
        };
        match role {
            KeyRole::Authorized => authorized = Some(new_id),
            KeyRole::Authentication => authentication = Some(new_id),
            KeyRole::Assertion => assertion = Some(new_id),
        }
    }

    // Each `Option` is `Some` here: rotated roles by the engine
    // call above; non-rotated roles by the validation loop. Unwrap
    // is safe by construction.
    let triple = KeyTriple {
        authorized: authorized.expect("authorized id populated above"),
        authentication: authentication.expect("authentication id populated above"),
        assertion: assertion.expect("assertion id populated above"),
    };
    let mut patch = Map::new();
    patch.insert("new_key_triple".into(), json!(triple));
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

    use chrono::Utc;
    use uuid::Uuid;

    use crate::domain::{
        GeneratedKeyPair, IssuerId, IssuerState, KeyAlgorithm, KeyPairId, RawPublicKey, TenantId,
    };
    use crate::worker::test_support::{GenerateKeypairCall, MockSigningEngine};

    fn fixture_kid(byte: u8) -> KeyPairId {
        let mut bytes = [byte; 16];
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        KeyPairId::from_uuid(Uuid::from_bytes(bytes))
    }

    fn fixture_generated(byte: u8, algorithm: KeyAlgorithm, pk_len: usize) -> GeneratedKeyPair {
        GeneratedKeyPair {
            id: fixture_kid(byte),
            public_key: RawPublicKey {
                algorithm,
                bytes: vec![byte; pk_len],
            },
        }
    }

    fn fixture_issuer() -> Issuer {
        Issuer {
            id: IssuerId::generate(),
            tenant_id: TenantId::generate(),
            did: "did:tdw:scid:reg.example.com:fixture-uuid".into(),
            state: Some(IssuerState::Active),
            description: Some("fixture".into()),
            authorized_key_id: Some(fixture_kid(0x01)),
            authentication_key_id: Some(fixture_kid(0x02)),
            assertion_key_id: Some(fixture_kid(0x03)),
            display_name: Some("Fixture".into()),
            logo_uri: None,
            locale: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn happy_path_single_role_rotates_only_authorized() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_generated(
            0xAA,
            KeyAlgorithm::Ed25519,
            32,
        )));

        let issuer = fixture_issuer();
        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized],
        };
        let state = RotateKeysStateData::default();

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Done(result) => {
                let triple = &result.state_data_patch["new_key_triple"];
                assert_eq!(triple["authorized"], json!(fixture_kid(0xAA)));
                assert_eq!(triple["authentication"], json!(fixture_kid(0x02)));
                assert_eq!(triple["assertion"], json!(fixture_kid(0x03)));
            }
            other => panic!("expected Done, got {other:?}"),
        }
        assert_eq!(
            engine.generate_invocations.lock().unwrap().as_slice(),
            &[KeyRole::Authorized],
        );
    }

    #[tokio::test]
    async fn happy_path_all_roles_rotates_all_three() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_generated(
            0xAA,
            KeyAlgorithm::Ed25519,
            32,
        )));
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_generated(
            0xBB,
            KeyAlgorithm::EcdsaP256,
            65,
        )));
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_generated(
            0xCC,
            KeyAlgorithm::EcdsaP256,
            65,
        )));

        let issuer = fixture_issuer();
        let input = RotateKeysInput {
            roles: vec![
                KeyRole::Authorized,
                KeyRole::Authentication,
                KeyRole::Assertion,
            ],
        };
        let state = RotateKeysStateData::default();

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Done(result) => {
                let triple = &result.state_data_patch["new_key_triple"];
                assert_eq!(triple["authorized"], json!(fixture_kid(0xAA)));
                assert_eq!(triple["authentication"], json!(fixture_kid(0xBB)));
                assert_eq!(triple["assertion"], json!(fixture_kid(0xCC)));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn skips_when_new_key_triple_already_set() {
        let engine = MockSigningEngine::new();
        // No generate calls enqueued — a call would panic.

        let issuer = fixture_issuer();
        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized],
        };
        let state = RotateKeysStateData {
            new_key_triple: Some(KeyTriple {
                authorized: fixture_kid(0x99),
                authentication: fixture_kid(0x02),
                assertion: fixture_kid(0x03),
            }),
            log_published: false,
        };

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(engine.generate_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn engine_backend_error_is_retryable() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Backend("hsm offline".into()));

        let issuer = fixture_issuer();
        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized],
        };
        let state = RotateKeysStateData::default();

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "generate_keypair_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn engine_unsupported_algorithm_is_terminal() {
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Unsupported);

        let issuer = fixture_issuer();
        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized],
        };
        let state = RotateKeysStateData::default();

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "generate_keypair_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_non_rotated_key_is_terminal() {
        // Issuer is missing `assertion_key_id` (e.g. a legacy /
        // half-migrated row). Rotating only `authorized` would carry
        // forward `None` for assertion — that's a corrupt state, so
        // the step refuses without calling the engine.
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.assertion_key_id = None;

        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized],
        };
        let state = RotateKeysStateData::default();

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_issuer_field");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(engine.generate_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_key_for_rotated_role_is_fine() {
        // The legacy issuer with `authorized_key_id = None` can still
        // be rotated *if* the request rotates the missing role: the
        // engine produces the new id, and there's no stale value to
        // carry forward.
        let engine = MockSigningEngine::new();
        engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_generated(
            0xAA,
            KeyAlgorithm::Ed25519,
            32,
        )));
        let mut issuer = fixture_issuer();
        issuer.authorized_key_id = None;

        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized],
        };
        let state = RotateKeysStateData::default();

        let outcome = execute_generate_new_keys(&issuer, &input, &state, &engine).await;

        match outcome {
            StepOutcome::Done(result) => {
                let triple = &result.state_data_patch["new_key_triple"];
                assert_eq!(triple["authorized"], json!(fixture_kid(0xAA)));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }
}
