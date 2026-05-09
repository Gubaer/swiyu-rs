//! `publish_log` step executor.
//!
//! Re-derives the genesis entry through `log_builder::build_log_entry`
//! and PUTs it to the SWIYU Identifier Registry. Idempotent on resume:
//! a second invocation observing `state_data.log_published == true`
//! returns immediately with no patch and no further engine or registry
//! call. The entry itself is not stored in `state_data` — re-derivation
//! is deterministic given the same key triple, allocation URL, and
//! `now`, which the dispatch loop pins to `task.created_at`.

use chrono::{DateTime, Utc};
use serde_json::{Map, json};

use crate::domain::{
    SigningEngine, SigningEngineError, StepOutcome, StepResult, Tenant, TokenProvider,
};
use crate::worker::registry_facades::{RegistryFacade, publish_log_entry_with_refresh};
use crate::worker::token_outcome::token_aware_error_to_outcome;

use super::CreateIssuerStateData;
use super::log_builder::{BuildError, build_log_entry};

pub async fn execute_publish_log<R: RegistryFacade, S: SigningEngine>(
    tenant: &Tenant,
    state: &CreateIssuerStateData,
    registry: &R,
    engine: &S,
    provider: &impl TokenProvider,
    now: DateTime<Utc>,
) -> StepOutcome {
    if state.log_published {
        return StepOutcome::Done(StepResult::default());
    }

    let partner_id = match tenant.partner_id.as_deref() {
        Some(p) => p,
        None => {
            return StepOutcome::Terminal {
                error_code: "tenant_missing_partner_id".into(),
                error_message: format!("tenant {} has no partner_id configured", tenant.id),
            };
        }
    };

    let identifier = match state.assigned_identifier.as_deref() {
        Some(i) => i,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing assigned_identifier".into(),
            };
        }
    };

    let entry = match build_log_entry(state, engine, now).await {
        Ok(e) => e,
        Err(BuildError::Engine(SigningEngineError::Backend(_))) => {
            return StepOutcome::Retry {
                error_code: "publish_log_failed".into(),
                error_message: "signing-engine backend error".into(),
            };
        }
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: e.error_code("publish_log_failed").into(),
                error_message: e.to_string(),
            };
        }
    };

    let line = serde_json::to_string(&entry).expect("entry value serialises");

    let result =
        publish_log_entry_with_refresh(provider, registry, partner_id, identifier, &line).await;

    match result {
        Ok(()) => {
            let mut patch = Map::new();
            patch.insert("log_published".into(), json!(true));
            StepOutcome::Done(StepResult {
                state_data_patch: patch,
            })
        }
        Err(e) => token_aware_error_to_outcome(e, "registry_unavailable", "registry_rejected"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use swiyu_registries::common::AccessToken;
    use uuid::Uuid;

    use crate::domain::{
        KeyAlgorithm, KeyPairId, RawPublicKey, Signature, StaticTokenProvider, TenantId,
    };
    use crate::worker::create_issuer::KeyTriple;
    use crate::worker::test_support::{
        AllocateCall, GetPublicKeyCall, MockRegistry, MockSigningEngine, PublishCall, SignCall,
    };

    fn fixture_kid(byte: u8) -> KeyPairId {
        let mut bytes = [byte; 16];
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        KeyPairId::from(Uuid::from_bytes(bytes))
    }

    fn fixture_state(log_published: bool) -> CreateIssuerStateData {
        CreateIssuerStateData {
            assigned_did_url: Some("https://reg.example.com/api/v1/did/abc/did.jsonl".into()),
            assigned_identifier: Some("abc".into()),
            key_ids: Some(KeyTriple {
                authorized: fixture_kid(0x11),
                authentication: fixture_kid(0x22),
                assertion: fixture_kid(0x33),
            }),
            log_published,
            status_list_registry_entry_id: None,
            status_list_registry_url: None,
        }
    }

    fn fixture_tenant(partner_id: Option<&str>) -> Tenant {
        Tenant {
            id: TenantId::generate(),
            partner_id: partner_id.map(str::to_string),
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_refresh_token: None,
        }
    }

    fn fixture_now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_768_982_400, 0).unwrap()
    }

    fn token_provider() -> StaticTokenProvider {
        StaticTokenProvider::new(AccessToken::new("test-token".to_string()))
    }

    fn fixture_ed25519_pk() -> RawPublicKey {
        RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0xab; 32],
        }
    }

    fn fixture_p256_pk() -> RawPublicKey {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(&[0xcd; 32]);
        bytes.extend_from_slice(&[0xef; 32]);
        RawPublicKey {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes,
        }
    }

    fn fixture_signature() -> Signature {
        Signature {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0x42; 64],
        }
    }

    fn engine_for_happy_path() -> MockSigningEngine {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_sign(SignCall::Ok(fixture_signature()));
        engine
    }

    #[tokio::test]
    async fn happy_path_publishes_and_marks_log_published() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::Ok);
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Done(result) => {
                assert_eq!(result.state_data_patch["log_published"], json!(true));
            }
            other => panic!("expected Done, got {other:?}"),
        }

        let publishes = registry.publish_invocations.lock().unwrap();
        assert_eq!(publishes.len(), 1);
        let (partner, identifier, entry) = &publishes[0];
        assert_eq!(partner, "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        assert_eq!(identifier, "abc");
        assert!(entry.starts_with('['), "entry is a JSON array");
    }

    #[tokio::test]
    async fn skips_when_log_already_published() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        // Deliberately enqueue nothing — a second call would panic.
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(true),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
        assert!(engine.public_key_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_partner_id_is_terminal() {
        let tenant = fixture_tenant(None);
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "tenant_missing_partner_id");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_assigned_identifier_is_terminal() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        let state = CreateIssuerStateData {
            assigned_identifier: None,
            ..fixture_state(false)
        };

        let outcome = execute_publish_log(
            &tenant,
            &state,
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_state");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_failure_routes_to_terminal() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        // Bad URL → BuildError::InvalidUrl → Terminal "invalid_allocation_url".
        let state = CreateIssuerStateData {
            assigned_did_url: Some("ftp://reg.example/did.jsonl".into()),
            ..fixture_state(false)
        };

        let outcome = execute_publish_log(
            &tenant,
            &state,
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_allocation_url");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn engine_backend_error_is_retryable() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Backend("connection refused".into()));

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "publish_log_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registry_5xx_is_retryable() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
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
    async fn registry_4xx_is_terminal() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 400,
            body: "bad entry".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
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
    async fn unused_allocate_queue_is_not_consumed() {
        // Sanity check that the publish path does not accidentally call
        // allocate_did. Enqueue a value the publish path must never read.
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::Ok);
        registry.enqueue_allocate(AllocateCall::HttpStatus {
            status: 500,
            body: "should never be consumed".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        assert!(matches!(outcome, StepOutcome::Done(_)));
        assert!(registry.allocate_invocations.lock().unwrap().is_empty());
    }
}
