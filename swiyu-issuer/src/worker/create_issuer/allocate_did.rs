//! Step 1 of the `CreateIssuer` saga: claim a DID at the SWIYU
//! Identifier Registry.

use serde_json::{Map, json};

use crate::domain::{StepOutcome, StepResult, Tenant, TokenProvider};
use crate::worker::create_issuer::CreateIssuerStateData;
use crate::worker::outcome::from_token_aware_error;
use crate::worker::registry_facades::{RegistryFacade, allocate_did_with_refresh};

/// Calls [`RegistryFacade::allocate_did`] and records the returned
/// URL and identifier in `state_data` so subsequent steps have
/// something to anchor on. The SWIYU API call is *not* idempotent —
/// a second call would mint a second DID — so on saga resume this
/// step short-circuits when `state_data.assigned_did_url` is already
/// set, returning [`StepOutcome::Done`] with no patch and no further
/// registry call.
pub async fn execute_allocate_did<R: RegistryFacade>(
    tenant: &Tenant,
    state: &CreateIssuerStateData,
    registry: &R,
    provider: &impl TokenProvider,
) -> StepOutcome {
    if state.assigned_did_url.is_some() {
        return StepOutcome::Done(StepResult::default());
    }

    let partner_id = tenant.partner_id.to_string();
    let result = allocate_did_with_refresh(provider, registry, &partner_id).await;

    match result {
        Ok(allocation) => {
            let mut patch = Map::new();
            patch.insert("assigned_did_url".into(), json!(allocation.url));
            patch.insert("assigned_identifier".into(), json!(allocation.identifier));
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

    use serde_json::Value;

    use crate::worker::test_support::{
        AllocateCall, MockRegistry, fixture_allocation, fixture_tenant, fixture_token_provider,
    };

    #[tokio::test]
    async fn happy_path_records_url_and_identifier() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::Ok(fixture_allocation()));

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
        )
        .await;

        match outcome {
            StepOutcome::Done(result) => {
                assert_eq!(
                    result.state_data_patch["assigned_did_url"],
                    Value::String("https://reg.example/api/v1/did/abc/did.jsonl".into()),
                );
                assert_eq!(
                    result.state_data_patch["assigned_identifier"],
                    Value::String("abc".into()),
                );
            }
            other => panic!("expected Done, got {other:?}"),
        }
        assert_eq!(
            registry.allocate_invocations.lock().unwrap().as_slice(),
            &["4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef".to_string()],
        );
    }

    #[tokio::test]
    async fn skips_when_assigned_did_url_already_set() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        // Deliberately enqueue nothing — a second call would panic.
        let state = CreateIssuerStateData {
            assigned_did_url: Some("https://reg.example/api/v1/did/abc/did.jsonl".into()),
            assigned_identifier: Some("abc".into()),
            ..CreateIssuerStateData::default()
        };

        let outcome =
            execute_allocate_did(&tenant, &state, &registry, &fixture_token_provider()).await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(registry.allocate_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registry_5xx_is_retryable() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
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
        // 400 rather than 401: a 401 now triggers a one-shot
        // refresh-and-retry through `with_refreshed_token`, so it is
        // no longer a single-call terminal failure. Any other 4xx
        // still maps straight to Terminal.
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::HttpStatus {
            status: 400,
            body: "bad request".into(),
        });

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
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
    async fn decode_error_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::Decode("malformed json".into()));

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "registry_rejected");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }
}
