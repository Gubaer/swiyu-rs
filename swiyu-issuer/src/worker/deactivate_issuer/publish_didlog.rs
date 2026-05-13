//! `publish_didlog` step executor for `DeactivateIssuer`.
//!
//! Re-fetches the DIDLog tail and re-derives the deactivation entry
//! through `didlog_builder::build_deactivation_entry`, then PUTs the
//! signed line to the SWIYU Identifier Registry. Idempotent on
//! resume: a second invocation observing `state_data.didlog_published
//! == true` returns immediately with no patch and no further engine,
//! registry, or signing call.
//!
//! Saga-resume after a crash *between* a successful PUT and the
//! state-patch write is handled by inspecting the registry's tail
//! itself: `build_deactivation_entry` returns
//! `BuildError::AlreadyDeactivated` when the registry already
//! holds a deactivation entry, and this executor maps that to
//! `Done` with the same `didlog_published = true` patch the success
//! path produces. A registry-side error response on the PUT
//! itself (some 4xx with a body identifying the DID as already
//! deactivated) would be a second place to land that branch; the
//! concrete error shape lands during integration testing.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde_json::{Map, json};

use swiyu_core::did::DID;

use crate::domain::{
    Issuer, SigningEngine, SigningEngineError, StepOutcome, StepResult, Tenant, TokenProvider,
};
use crate::worker::didlog_common::ChainedBuildError;
use crate::worker::outcome::from_token_aware_error;
use crate::worker::registry_facades::{
    RegistryFacade, build_updated_didlog, publish_log_entry_with_refresh,
};

use super::didlog_builder::{BuildError, build_deactivation_entry};
use super::state::DeactivateIssuerStateData;
use crate::worker::registry_identifier;

pub async fn execute_publish_didlog<R: RegistryFacade, S: SigningEngine>(
    tenant: &Tenant,
    issuer: &Issuer,
    state: &DeactivateIssuerStateData,
    registry: &R,
    engine: &S,
    provider: &impl TokenProvider,
    now: DateTime<Utc>,
) -> StepOutcome {
    if state.didlog_published {
        return StepOutcome::Done(StepResult::default());
    }

    let partner_id = tenant.partner_id.to_string();

    let did = match DID::from_str(&issuer.did) {
        Ok(d) => d,
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: "invalid_issuer_did".into(),
                error_message: format!("cannot parse issuer did {}: {e}", issuer.did),
            };
        }
    };
    let identifier = match registry_identifier(&did) {
        Some(i) => i,
        None => {
            return StepOutcome::Terminal {
                error_code: "invalid_issuer_did".into(),
                error_message: format!(
                    "cannot extract registry identifier from did: {}",
                    issuer.did
                ),
            };
        }
    };

    let fetched = match registry.fetch_log(&did).await {
        Ok(f) => f,
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

    let entry = match build_deactivation_entry(issuer, &fetched.entries, engine, now).await {
        Ok(e) => e,
        // Saga resume: a previous publish already wrote the
        // deactivation entry; the registry tail is already
        // deactivated. Mark the step Done and let mark_deactivated
        // run.
        Err(BuildError::AlreadyDeactivated) => {
            return StepOutcome::Done(state_patch_didlog_published());
        }
        Err(BuildError::Chained(ChainedBuildError::Engine(SigningEngineError::Backend(_)))) => {
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

    // The SWIYU registry's PUT endpoint replaces the whole DIDLog,
    // not appends. We send the prior entries verbatim followed by
    // the new one — see `build_updated_didlog`.
    let new_line = serde_json::to_string(&entry).expect("entry value serialises");
    let updated_didlog = build_updated_didlog(&fetched.raw, &new_line);

    let result = publish_log_entry_with_refresh(
        provider,
        registry,
        &partner_id,
        &identifier,
        &updated_didlog,
    )
    .await;

    match result {
        Ok(()) => StepOutcome::Done(state_patch_didlog_published()),
        Err(e) => from_token_aware_error(e, "registry_unavailable", "registry_rejected"),
    }
}

fn state_patch_didlog_published() -> StepResult {
    let mut patch = Map::new();
    patch.insert("didlog_published".into(), json!(true));
    StepResult {
        state_data_patch: patch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use swiyu_registries::common::AccessToken;

    use swiyu_core::diddoc::DIDDoc;
    use swiyu_core::didlog::{DIDLogEntry, LogEntryFormat};

    use crate::domain::signing_engine::test_support::{
        GetPublicKeyCall, MockSigningEngine, SignCall, fixture_ed25519_pk, fixture_signature,
    };
    use crate::domain::{Issuer, IssuerId, IssuerState, StaticTokenProvider, TenantId};
    use crate::worker::test_support::{
        FIXTURE_DID_REGISTRY_UUID, FetchLogCall, MockRegistry, PublishCall, fixture_did,
        fixture_kid, fixture_now, fixture_p256,
    };

    fn fixture_issuer() -> Issuer {
        Issuer {
            id: IssuerId::generate(),
            tenant_id: TenantId::generate(),
            did: fixture_did().into(),
            state: Some(IssuerState::Active),
            description: Some("fixture".into()),
            authorized_key_id: Some(fixture_kid(0x11)),
            authentication_key_id: Some(fixture_kid(0x22)),
            assertion_key_id: Some(fixture_kid(0x33)),
            display_name: Some("Fixture".into()),
            logo_uri: None,
            locale: None,
            created_at: Utc::now(),
        }
    }

    fn fixture_state(didlog_published: bool) -> DeactivateIssuerStateData {
        DeactivateIssuerStateData { didlog_published }
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

    fn fixture_genesis_entry() -> DIDLogEntry {
        DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            "z6Mk-authorized-fixture",
            fixture_did(),
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T12:00:00Z",
        )
    }

    fn fixture_deactivation_entry() -> DIDLogEntry {
        let prev_doc = DIDDoc::new_genesis(fixture_did(), &fixture_p256(), &fixture_p256());
        DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrev",
            &prev_doc,
            "2026-05-04T13:00:00Z",
        )
    }

    fn engine_for_happy_path() -> MockSigningEngine {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_sign(SignCall::Ok(fixture_signature()));
        engine
    }

    #[tokio::test]
    async fn happy_path_publishes_and_marks_didlog_published() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        registry.enqueue_publish(PublishCall::Ok);
        let engine = engine_for_happy_path();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
        assert_eq!(identifier, FIXTURE_DID_REGISTRY_UUID);
        assert!(
            entry.starts_with('['),
            "entry is a JSON array (did:tdw 0.3 wire form)"
        );
    }

    #[tokio::test]
    async fn skips_when_log_already_published() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        // No fetch_log or publish queued — a second call would panic.
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
        assert!(registry.fetch_log_invocations.lock().unwrap().is_empty());
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
        assert!(engine.public_key_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn already_deactivated_tail_is_done_with_patch() {
        // Saga resume: the previous publish_didlog already pushed the
        // deactivation entry, but state_data.didlog_published wasn't
        // recorded. Re-running the step must observe the deactivated
        // tail and return Done with the patch, *not* republish.
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![
            fixture_genesis_entry(),
            fixture_deactivation_entry(),
        ]));
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
        assert!(engine.public_key_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unparseable_did_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.did = "not a did".into();

        let outcome = execute_publish_didlog(
            &tenant,
            &issuer,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "invalid_issuer_did");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.fetch_log_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_log_5xx_is_retryable() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_log_404_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 404,
            body: "unknown identifier".into(),
        });
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
    async fn engine_backend_error_is_retryable() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Backend("hsm offline".into()));

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
    async fn sign_key_not_found_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_sign(SignCall::NotFound(fixture_kid(0x11)));

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "publish_didlog_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_5xx_is_retryable() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
    async fn publish_4xx_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 400,
            body: "bad entry".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
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
    async fn issuer_not_active_is_terminal() {
        // build_deactivation_entry rejects non-Active issuers.
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.state = Some(IssuerState::Deactivated);

        let outcome = execute_publish_didlog(
            &tenant,
            &issuer,
            &fixture_state(false),
            &registry,
            &engine,
            &token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "issuer_not_active");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }
}
