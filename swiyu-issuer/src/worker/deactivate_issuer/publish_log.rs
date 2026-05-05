//! `publish_log` step executor for `DeactivateIssuer`.
//!
//! Re-fetches the DIDLog tail and re-derives the deactivation entry
//! through `log_builder::build_deactivation_entry`, then PUTs the
//! signed line to the SWIYU Identifier Registry. Idempotent on
//! resume: a second invocation observing `state_data.log_published
//! == true` returns immediately with no patch and no further engine,
//! registry, or signing call.
//!
//! Saga-resume after a crash *between* a successful PUT and the
//! state-patch write is handled by inspecting the registry's tail
//! itself: `build_deactivation_entry` returns
//! [`BuildError::AlreadyDeactivated`] when the registry already
//! holds a deactivation entry, and this executor maps that to
//! `Done` with the same `log_published = true` patch the success
//! path produces. A registry-side error response on the PUT
//! itself (some 4xx with a body identifying the DID as already
//! deactivated) would be a second place to land that branch; the
//! concrete error shape lands during integration testing.

use chrono::{DateTime, Utc};
use serde_json::{Map, json};

use crate::domain::{Issuer, SigningEngine, SigningEngineError, StepOutcome, StepResult, Tenant};
use crate::worker::registry::RegistryFacade;

use super::log_builder::{BuildError, build_deactivation_entry};
use super::registry_identifier;
use super::state::DeactivateIssuerStateData;

pub async fn execute_publish_log<R: RegistryFacade, S: SigningEngine>(
    tenant: &Tenant,
    issuer: &Issuer,
    state: &DeactivateIssuerStateData,
    registry: &R,
    engine: &S,
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

    let identifier = match registry_identifier(&issuer.did) {
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

    let log = match registry.fetch_log(&identifier).await {
        Ok(entries) => entries,
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

    let entry = match build_deactivation_entry(issuer, &log, engine, now).await {
        Ok(e) => e,
        // Saga resume: a previous publish already wrote the
        // deactivation entry; the registry tail is already
        // deactivated. Mark the step Done and let mark_deactivated
        // run.
        Err(BuildError::AlreadyDeactivated) => {
            return StepOutcome::Done(state_patch_log_published());
        }
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

    match registry
        .publish_log_entry(partner_id, &identifier, &line)
        .await
    {
        Ok(()) => StepOutcome::Done(state_patch_log_published()),
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

fn state_patch_log_published() -> StepResult {
    let mut patch = Map::new();
    patch.insert("log_published".into(), json!(true));
    StepResult {
        state_data_patch: patch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::Uuid;

    use swiyu_core::diddoc::DIDDoc;
    use swiyu_core::diddoc::public_keys::P256PublicKey;
    use swiyu_core::didlog::{DIDLogEntry, LogEntryFormat};

    use crate::domain::{
        Issuer, IssuerId, IssuerState, KeyAlgorithm, KeyPairId, RawPublicKey, Signature, TenantId,
    };
    use crate::worker::test_support::{
        FetchLogCall, GetPublicKeyCall, MockRegistry, MockSigningEngine, PublishCall, SignCall,
    };

    fn fixture_kid(byte: u8) -> KeyPairId {
        let mut bytes = [byte; 16];
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        KeyPairId::from_uuid(Uuid::from_bytes(bytes))
    }

    fn fixture_p256() -> P256PublicKey {
        P256PublicKey {
            x: [1u8; 32],
            y: [2u8; 32],
        }
    }

    const FIXTURE_UUID: &str = "fce949f2-32c4-4915-8b60-0ee2f705231d";

    fn fixture_did() -> String {
        format!("did:tdw:reg.example.com:{FIXTURE_UUID}:scid-placeholder")
    }

    fn fixture_issuer() -> Issuer {
        Issuer {
            id: IssuerId::generate(),
            tenant_id: TenantId::generate(),
            did: fixture_did(),
            state: Some(IssuerState::Active),
            description: Some("fixture".into()),
            authorized_key_id: Some(fixture_kid(0x11)),
            authentication_key_id: Some(fixture_kid(0x22)),
            assertion_key_id: Some(fixture_kid(0x33)),
            signing_key_id: None,
            display_name: Some("Fixture".into()),
            logo_uri: None,
            locale: None,
            created_at: Utc::now(),
        }
    }

    fn fixture_state(log_published: bool) -> DeactivateIssuerStateData {
        DeactivateIssuerStateData { log_published }
    }

    fn fixture_tenant(partner_id: Option<&str>) -> Tenant {
        Tenant {
            id: TenantId::generate(),
            partner_id: partner_id.map(str::to_string),
        }
    }

    fn fixture_now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_768_982_400, 0).unwrap()
    }

    fn fixture_genesis_entry() -> DIDLogEntry {
        DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            "z6Mk-authorized-fixture",
            &fixture_did(),
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T12:00:00Z",
        )
    }

    fn fixture_deactivation_entry() -> DIDLogEntry {
        let prev_doc = DIDDoc::new_genesis(&fixture_did(), &fixture_p256(), &fixture_p256());
        DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrev",
            &prev_doc,
            "2026-05-04T13:00:00Z",
        )
    }

    fn fixture_ed25519_pk() -> RawPublicKey {
        RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0xab; 32],
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
        engine.enqueue_sign(SignCall::Ok(fixture_signature()));
        engine
    }

    #[tokio::test]
    async fn happy_path_publishes_and_marks_log_published() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        registry.enqueue_publish(PublishCall::Ok);
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
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
        assert_eq!(identifier, FIXTURE_UUID);
        assert!(
            entry.starts_with('['),
            "entry is a JSON array (did:tdw 0.3 wire form)"
        );
    }

    #[tokio::test]
    async fn skips_when_log_already_published() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        // No fetch_log or publish queued — a second call would panic.
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(true),
            &registry,
            &engine,
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
        // Saga resume: the previous publish_log already pushed the
        // deactivation entry, but state_data.log_published wasn't
        // recorded. Re-running the step must observe the deactivated
        // tail and return Done with the patch, *not* republish.
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![
            fixture_genesis_entry(),
            fixture_deactivation_entry(),
        ]));
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Done(result) => {
                assert_eq!(result.state_data_patch["log_published"], json!(true));
            }
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
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "tenant_missing_partner_id");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        assert!(registry.fetch_log_invocations.lock().unwrap().is_empty());
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unparseable_did_is_terminal() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.did = "not a did".into();

        let outcome = execute_publish_log(
            &tenant,
            &issuer,
            &fixture_state(false),
            &registry,
            &engine,
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
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
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
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::HttpStatus {
            status: 404,
            body: "unknown identifier".into(),
        });
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
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
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Backend("hsm offline".into()));

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
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
    async fn sign_key_not_found_is_terminal() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_sign(SignCall::NotFound(fixture_kid(0x11)));

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "publish_log_failed");
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_5xx_is_retryable() {
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 503,
            body: "service unavailable".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
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
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        registry.enqueue_publish(PublishCall::HttpStatus {
            status: 400,
            body: "bad entry".into(),
        });
        let engine = engine_for_happy_path();

        let outcome = execute_publish_log(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false),
            &registry,
            &engine,
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
        let tenant = fixture_tenant(Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"));
        let registry = MockRegistry::new();
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
        let engine = MockSigningEngine::new();
        let mut issuer = fixture_issuer();
        issuer.state = Some(IssuerState::Deactivated);

        let outcome = execute_publish_log(
            &tenant,
            &issuer,
            &fixture_state(false),
            &registry,
            &engine,
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
