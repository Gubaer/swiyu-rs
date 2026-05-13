//! Step 4 of the `CreateIssuer` saga: PUT the signed genesis DIDLog
//! entry to the SWIYU Identifier Registry.

use chrono::{DateTime, Utc};
use serde_json::{Map, json};

use crate::domain::{
    SigningEngine, SigningEngineError, StepOutcome, StepResult, Tenant, TokenProvider,
};
use crate::worker::outcome::from_token_aware_error;
use crate::worker::registry_facades::{RegistryFacade, publish_log_entry_with_refresh};

use super::CreateIssuerStateData;
use super::didlog_builder::{BuildError, build_log_entry};

/// Re-derives the genesis entry through
/// [`super::didlog_builder::build_log_entry`] and sends it to the
/// registry. The entry itself is not stored in `state_data` —
/// re-derivation is deterministic given the same key triple,
/// allocation URL, and `now`, which the dispatch loop pins to
/// `task.created_at`. On saga resume this step short-circuits when
/// `state_data.didlog_published == true`, returning [`StepOutcome::Done`]
/// with no further engine or registry call.
pub async fn execute_publish_didlog<R: RegistryFacade, S: SigningEngine>(
    tenant: &Tenant,
    state: &CreateIssuerStateData,
    registry: &R,
    engine: &S,
    provider: &impl TokenProvider,
    now: DateTime<Utc>,
) -> StepOutcome {
    if state.didlog_published {
        return StepOutcome::Done(StepResult::default());
    }

    let partner_id = tenant.partner_id.to_string();

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
                error_code: "publish_didlog_failed".into(),
                error_message: "signing-engine backend error".into(),
            };
        }
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: e.error_code("publish_didlog_failed").into(),
                error_message: e.to_string(),
            };
        }
    };

    let line = serde_json::to_string(&entry).expect("entry value serialises");

    let result =
        publish_log_entry_with_refresh(provider, registry, &partner_id, identifier, &line).await;

    match result {
        Ok(()) => {
            let mut patch = Map::new();
            patch.insert("didlog_published".into(), json!(true));
            StepOutcome::Done(StepResult {
                state_data_patch: patch,
            })
        }
        Err(e) => from_token_aware_error(e, "registry_unavailable", "registry_rejected"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use swiyu_registries::common::AccessToken;

    use crate::domain::signing_engine::test_support::{GetPublicKeyCall, MockSigningEngine};
    use crate::domain::{StaticTokenProvider, TenantId};
    use crate::worker::create_issuer::KeyTriple;
    use crate::worker::test_support::{
        AllocateCall, MockRegistry, PublishCall, fixture_kid, fixture_now,
    };

    fn fixture_state(didlog_published: bool) -> CreateIssuerStateData {
        CreateIssuerStateData {
            assigned_did_url: Some("https://reg.example.com/api/v1/did/abc/did.jsonl".into()),
            assigned_identifier: Some("abc".into()),
            key_ids: Some(KeyTriple {
                authorized: fixture_kid(0x11),
                authentication: fixture_kid(0x22),
                assertion: fixture_kid(0x33),
            }),
            didlog_published,
            status_list_registry_entry_id: None,
            status_list_registry_url: None,
        }
    }

    fn fixture_tenant(partner_id: &str) -> Tenant {
        Tenant {
            id: TenantId::generate(),
            partner_id: partner_id
                .parse()
                .expect("test partner_id must be a valid UUID"),
            display_name: None,
            description: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_refresh_token: None,
        }
    }

    fn token_provider() -> StaticTokenProvider {
        StaticTokenProvider::new(AccessToken::new("test-token".to_string()))
    }

    #[tokio::test]
    async fn happy_path_publishes_and_marks_didlog_published() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::Ok);
        let engine = MockSigningEngine::for_happy_path();

        let outcome = execute_publish_didlog(
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
                assert_eq!(result.state_data_patch["didlog_published"], json!(true));
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        // Deliberately enqueue nothing — a second call would panic.
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_didlog(
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
    async fn missing_assigned_identifier_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        let state = CreateIssuerStateData {
            assigned_identifier: None,
            ..fixture_state(false)
        };

        let outcome = execute_publish_didlog(
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        // Bad URL → BuildError::InvalidUrl → Terminal "invalid_allocation_url".
        let state = CreateIssuerStateData {
            assigned_did_url: Some("ftp://reg.example/did.jsonl".into()),
            ..fixture_state(false)
        };

        let outcome = execute_publish_didlog(
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Backend("connection refused".into()));

        let outcome = execute_publish_didlog(
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
                assert_eq!(error_code, "publish_didlog_failed");
            }
            other => panic!("expected Retry, got {other:?}"),
        }
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registry_5xx_is_retryable() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = MockSigningEngine::for_happy_path();

        let outcome = execute_publish_didlog(
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 400,
            body: "bad entry".into(),
        });
        let engine = MockSigningEngine::for_happy_path();

        let outcome = execute_publish_didlog(
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_publish(PublishCall::Ok);
        registry.enqueue_allocate(AllocateCall::HttpStatus {
            status: 500,
            body: "should never be consumed".into(),
        });
        let engine = MockSigningEngine::for_happy_path();

        let outcome = execute_publish_didlog(
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
