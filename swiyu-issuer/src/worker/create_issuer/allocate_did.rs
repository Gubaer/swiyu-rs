//! `allocate_did` step executor.
//!
//! Calls `RegistryFacade::allocate_did(partner_id)` and records the
//! returned URL and identifier in `state_data`. Idempotent on resume:
//! a second invocation observing `state_data.assigned_did_url` set
//! returns immediately with no patch and no further registry call.

use serde_json::{Map, json};
use swiyu_registries::common::AccessToken;

use crate::domain::{StepOutcome, StepResult, Tenant};
use crate::worker::create_issuer::CreateIssuerStateData;
use crate::worker::registry::RegistryFacade;

pub async fn execute_allocate_did<R: RegistryFacade>(
    tenant: &Tenant,
    state: &CreateIssuerStateData,
    registry: &R,
    token: &AccessToken,
) -> StepOutcome {
    if state.assigned_did_url.is_some() {
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

    match registry.allocate_did(token, partner_id).await {
        Ok(allocation) => {
            let mut patch = Map::new();
            patch.insert("assigned_did_url".into(), json!(allocation.url));
            patch.insert("assigned_identifier".into(), json!(allocation.identifier));
            StepOutcome::Done(StepResult {
                state_data_patch: patch,
            })
        }
        Err(e) if e.is_retryable() => StepOutcome::Retry {
            error_code: "registry_unavailable".into(),
            error_message: e.to_string(),
        },
        Err(e) => StepOutcome::Terminal {
            error_code: "registry_rejected".into(),
            error_message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;
    use swiyu_registries::identifier::Allocation;

    use crate::domain::TenantId;
    use crate::worker::test_support::{AllocateCall, MockRegistry};

    fn tenant_with_partner(partner_id: &str) -> Tenant {
        Tenant {
            id: TenantId::generate(),
            partner_id: Some(partner_id.into()),
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_refresh_token: None,
        }
    }

    fn token() -> AccessToken {
        AccessToken::new("test-token".to_string())
    }

    fn fixture_allocation() -> Allocation {
        Allocation {
            url: "https://reg.example/api/v1/did/abc/did.jsonl".into(),
            identifier: "abc".into(),
        }
    }

    #[tokio::test]
    async fn happy_path_records_url_and_identifier() {
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::Ok(fixture_allocation()));

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
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
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        // Deliberately enqueue nothing — a second call would panic.
        let state = CreateIssuerStateData {
            assigned_did_url: Some("https://reg.example/api/v1/did/abc/did.jsonl".into()),
            assigned_identifier: Some("abc".into()),
            ..CreateIssuerStateData::default()
        };

        let outcome = execute_allocate_did(&tenant, &state, &registry, &token()).await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(registry.allocate_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_partner_id_is_terminal() {
        let tenant = Tenant {
            id: TenantId::generate(),
            partner_id: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_refresh_token: None,
        };
        let registry = MockRegistry::new();

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "tenant_missing_partner_id");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.allocate_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registry_5xx_is_retryable() {
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
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
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::HttpStatus {
            status: 401,
            body: "unauthorized".into(),
        });

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
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
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::Decode("malformed json".into()));

        let outcome = execute_allocate_did(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
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
