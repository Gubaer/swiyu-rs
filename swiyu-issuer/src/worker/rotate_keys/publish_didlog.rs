//! `publish_didlog` step executor for `RotateKeys`.
//!
//! Re-fetches the DIDLog tail and re-derives the rotation entry
//! through `didlog_builder::build_rotation_entry`, then PUTs the
//! signed line to the SWIYU Identifier Registry. Idempotent on
//! resume: a second invocation observing
//! `state_data.didlog_published == true` returns immediately with no
//! patch and no further engine, registry, or signing call.
//!
//! Saga-resume after a crash *between* a successful PUT and the
//! state-patch write is handled by inspecting the registry's tail
//! itself: `build_rotation_entry` returns
//! `BuildError::AlreadyRotated` when the registry tail's
//! `updateKeys[0]` already matches the multikey of
//! `state.new_key_triple.authorized` (i.e. the rotation entry was
//! already published). This executor maps that to `Done` with the
//! same `didlog_published = true` patch the success path produces.

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
use crate::worker::registry_identifier;

use super::didlog_builder::{BuildError, build_rotation_entry};
use super::state::RotateKeysStateData;

pub async fn execute_publish_didlog<R: RegistryFacade, S: SigningEngine>(
    tenant: &Tenant,
    issuer: &Issuer,
    state: &RotateKeysStateData,
    registry: &R,
    engine: &S,
    provider: &impl TokenProvider,
    now: DateTime<Utc>,
) -> StepOutcome {
    if state.didlog_published {
        return StepOutcome::Done(StepResult::default());
    }

    let new_triple = match state.new_key_triple.as_ref() {
        Some(t) => t,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing new_key_triple".into(),
            };
        }
    };

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

    let entry = match build_rotation_entry(issuer, new_triple, &fetched.entries, engine, now).await
    {
        Ok(e) => e,
        // Saga resume: a previous publish already wrote the
        // rotation entry; the registry tail's updateKeys[0]
        // already matches the new authorized's multikey. Mark
        // the step Done and let swap_keys run.
        Err(BuildError::AlreadyRotated) => {
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

    use swiyu_core::didlog::{DIDLogEntry, LogEntryFormat};

    use crate::domain::{KeyAlgorithm, RawPublicKey};
    use crate::test_support::domain::signing_engine::{
        GetPublicKeyCall, MockSigningEngine, SignCall, fixture_p256_pk, fixture_signature,
    };
    use crate::test_support::worker::{
        FIXTURE_DID_REGISTRY_UUID, FetchLogCall, MockRegistry, PublishCall, fixture_did,
        fixture_issuer, fixture_now, fixture_p256, fixture_rotated_triple, fixture_tenant,
        fixture_token_provider,
    };

    fn fixture_state(didlog_published: bool, with_triple: bool) -> RotateKeysStateData {
        RotateKeysStateData {
            new_key_triple: with_triple.then(fixture_rotated_triple),
            didlog_published,
        }
    }

    fn fixture_genesis_entry() -> DIDLogEntry {
        crate::test_support::worker::fixture_genesis_entry("z6Mk-old-authorized")
    }

    fn fixture_ed25519_pk(seed: u8) -> RawPublicKey {
        RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![seed; 32],
        }
    }

    fn engine_for_happy_path() -> MockSigningEngine {
        let engine = MockSigningEngine::new();
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0xAA))); // new authorized
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk())); // new authentication
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk())); // new assertion
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0x11))); // outgoing authorized
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
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
            &fixture_state(true, true),
            &registry,
            &engine,
            &fixture_token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
            other => panic!("expected Done, got {other:?}"),
        }
        assert!(registry.fetch_log_invocations.lock().unwrap().is_empty());
        assert!(registry.publish_invocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn already_rotated_tail_is_done_with_patch() {
        // Saga resume: the previous publish_didlog already pushed the
        // rotation entry. The registry tail's updateKeys[0] already
        // matches the new authorized's multikey. Re-running the step
        // must observe that and return Done with the patch, *not*
        // republish.
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();

        let new_authorized_multikey =
            swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey(&[0xAA; 32]);
        let already_rotated_tail = DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            &new_authorized_multikey,
            fixture_did(),
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T12:00:00Z",
        );
        registry.enqueue_fetch_log(FetchLogCall::Ok(vec![already_rotated_tail]));

        let engine = MockSigningEngine::new();
        // The check happens after fetching the three new public keys.
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0xAA)));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
    }

    #[tokio::test]
    async fn missing_new_key_triple_is_terminal() {
        let tenant = fixture_tenant("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef");
        let registry = MockRegistry::new();
        let engine = MockSigningEngine::new();

        let outcome = execute_publish_didlog(
            &tenant,
            &fixture_issuer(),
            &fixture_state(false, false),
            &registry,
            &engine,
            &fixture_token_provider(),
            fixture_now(),
        )
        .await;

        match outcome {
            StepOutcome::Terminal { error_code, .. } => {
                assert_eq!(error_code, "missing_state");
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
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
            &fixture_state(false, true),
            &registry,
            &engine,
            &fixture_token_provider(),
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
}
