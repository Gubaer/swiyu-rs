//! Step 6 of the `CreateIssuer` saga: allocate the issuer's first
//! status-list entry at the SWIYU Status Registry.

use serde_json::{Map, json};

use crate::domain::{StepOutcome, StepResult, Tenant, TokenProvider};
use crate::worker::create_issuer::CreateIssuerStateData;
use crate::worker::outcome::from_token_aware_error;
use crate::worker::registry_facades::{
    StatusRegistryFacade, create_status_list_entry_with_refresh,
};

/// Calls [`StatusRegistryFacade::create_status_list_entry`] and
/// records the returned `id` and `registry_url` in `state_data`. The
/// registry call is *not* idempotent server-side — each successful
/// call mints a fresh entry — so on saga resume this step
/// short-circuits when `state_data.status_list_registry_entry_id` is
/// already set, returning [`StepOutcome::Done`] with no further
/// registry call. The state-data marker is the load-bearing
/// safeguard against duplicate entries on retry.
pub async fn execute_create_status_list_entry<C: StatusRegistryFacade>(
    tenant: &Tenant,
    state: &CreateIssuerStateData,
    status_registry: &C,
    provider: &impl TokenProvider,
) -> StepOutcome {
    if state.status_list_registry_entry_id.is_some() {
        return StepOutcome::Done(StepResult::default());
    }

    let partner_id = tenant.partner_id.to_string();
    let result =
        create_status_list_entry_with_refresh(provider, status_registry, &partner_id).await;

    match result {
        Ok(entry) => {
            let mut patch = Map::new();
            patch.insert("status_list_registry_entry_id".into(), json!(entry.id));
            patch.insert("status_list_registry_url".into(), json!(entry.registry_url));
            StepOutcome::Done(StepResult {
                state_data_patch: patch,
            })
        }
        Err(e) => {
            from_token_aware_error(e, "status_registry_unavailable", "status_registry_rejected")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;
    use swiyu_registries::status::StatusListEntry;

    use crate::test_support::worker::{
        CreateStatusListEntryCall, MockStatusRegistry, fixture_tenant, fixture_token_provider,
    };

    fn fixture_entry() -> StatusListEntry {
        StatusListEntry {
            id: "11111111-2222-3333-4444-555555555555".into(),
            registry_url: "https://status-reg.example.com/lists/abc.jwt".into(),
        }
    }

    #[tokio::test]
    async fn happy_path_records_entry_id_and_url() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        registry.enqueue_create(CreateStatusListEntryCall::Ok(fixture_entry()));

        let outcome = execute_create_status_list_entry(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        // No queued response; if the executor calls the registry the
        // mock will panic on the missing queue entry.

        let state = CreateIssuerStateData {
            status_list_registry_entry_id: Some(fixture_entry().id),
            status_list_registry_url: Some(fixture_entry().registry_url),
            ..CreateIssuerStateData::default()
        };
        let outcome =
            execute_create_status_list_entry(&tenant, &state, &registry, &fixture_token_provider())
                .await;

        match outcome {
            StepOutcome::Done(StepResult { state_data_patch }) => {
                assert!(state_data_patch.is_empty(), "no patch on resume");
            }
            other => panic!("expected Done; got {other:?}"),
        }
        assert!(registry.create_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retryable_status_yields_retry() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        registry.enqueue_create(CreateStatusListEntryCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });

        let outcome = execute_create_status_list_entry(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
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
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockStatusRegistry::new();
        registry.enqueue_create(CreateStatusListEntryCall::HttpStatus {
            status: 403,
            body: "forbidden".into(),
        });

        let outcome = execute_create_status_list_entry(
            &tenant,
            &CreateIssuerStateData::default(),
            &registry,
            &fixture_token_provider(),
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
