//! `create_status_list_entry` step executor.
//!
//! Calls `StatusRegistryFacade::create_status_list_entry(partner_id)`
//! and records the returned `id` and `registry_url` in `state_data`.
//! Idempotent on resume: a second invocation observing
//! `state_data.status_list_registry_entry_id` set returns immediately
//! with no patch and no further registry call. The registry call is
//! **not idempotent** server-side (every successful call mints a fresh
//! entry), so the state-data marker is the load-bearing safeguard
//! against duplicate entries on retry.

use serde_json::{Map, json};
use swiyu_registries::common::AccessToken;

use crate::domain::{StepOutcome, StepResult, Tenant};
use crate::worker::create_issuer::CreateIssuerStateData;
use crate::worker::registry::StatusRegistryFacade;

pub async fn execute_create_status_list_entry<C: StatusRegistryFacade>(
    tenant: &Tenant,
    state: &CreateIssuerStateData,
    status_registry: &C,
    token: &AccessToken,
) -> StepOutcome {
    if state.status_list_registry_entry_id.is_some() {
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

    match status_registry
        .create_status_list_entry(token, partner_id)
        .await
    {
        Ok(entry) => {
            let mut patch = Map::new();
            patch.insert("status_list_registry_entry_id".into(), json!(entry.id));
            patch.insert("status_list_registry_url".into(), json!(entry.registry_url));
            StepOutcome::Done(StepResult {
                state_data_patch: patch,
            })
        }
        Err(e) if e.is_retryable() => StepOutcome::Retry {
            error_code: "status_registry_unavailable".into(),
            error_message: e.to_string(),
        },
        Err(e) => StepOutcome::Terminal {
            error_code: "status_registry_rejected".into(),
            error_message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;
    use swiyu_registries::status::StatusListEntry;

    use crate::domain::TenantId;
    use crate::worker::test_support::{CreateStatusListEntryCall, MockStatusRegistry};

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

    fn fixture_entry() -> StatusListEntry {
        StatusListEntry {
            id: "11111111-2222-3333-4444-555555555555".into(),
            registry_url: "https://status-reg.example.com/lists/abc.jwt".into(),
        }
    }

    #[tokio::test]
    async fn happy_path_records_entry_id_and_url() {
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        registry.enqueue_create(CreateStatusListEntryCall::Ok(fixture_entry()));

        let outcome = execute_create_status_list_entry(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
        )
        .await;

        let patch = match outcome {
            StepOutcome::Done(StepResult { state_data_patch }) => state_data_patch,
            other => panic!("expected Done; got {other:?}"),
        };
        assert_eq!(
            patch.get("status_list_registry_entry_id"),
            Some(&Value::String(fixture_entry().id))
        );
        assert_eq!(
            patch.get("status_list_registry_url"),
            Some(&Value::String(fixture_entry().registry_url))
        );
        assert_eq!(
            *registry.create_invocations.lock().unwrap(),
            vec!["4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef".to_string()]
        );
    }

    #[tokio::test]
    async fn idempotent_on_resume_skips_registry_call() {
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        // No queued response; if the executor calls the registry the
        // mock will panic on the missing queue entry.

        let state = CreateIssuerStateData {
            status_list_registry_entry_id: Some(fixture_entry().id),
            status_list_registry_url: Some(fixture_entry().registry_url),
            ..CreateIssuerStateData::default()
        };
        let outcome = execute_create_status_list_entry(&tenant, &state, &registry, &token()).await;

        match outcome {
            StepOutcome::Done(StepResult { state_data_patch }) => {
                assert!(state_data_patch.is_empty(), "no patch on resume");
            }
            other => panic!("expected Done; got {other:?}"),
        }
        assert!(registry.create_invocations.lock().unwrap().is_empty());
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
        let registry = MockStatusRegistry::new();

        let outcome = execute_create_status_list_entry(
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
            other => panic!("expected Terminal; got {other:?}"),
        }
        assert!(registry.create_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retryable_status_yields_retry() {
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        registry.enqueue_create(CreateStatusListEntryCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });

        let outcome = execute_create_status_list_entry(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
        )
        .await;

        match outcome {
            StepOutcome::Retry { error_code, .. } => {
                assert_eq!(error_code, "status_registry_unavailable");
            }
            other => panic!("expected Retry; got {other:?}"),
        }
    }

    #[tokio::test]
    async fn terminal_status_yields_terminal() {
        let tenant = tenant_with_partner("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        registry.enqueue_create(CreateStatusListEntryCall::HttpStatus {
            status: 403,
            body: "forbidden".into(),
        });

        let outcome = execute_create_status_list_entry(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &token(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "status_registry_rejected");
            }
            other => panic!("expected Terminal; got {other:?}"),
        }
    }
}
