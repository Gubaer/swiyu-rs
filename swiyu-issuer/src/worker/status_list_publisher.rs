//! Publish loop for status lists.
//!
//! Second tokio task alongside [`crate::worker::Worker`]. Polls
//! `persistence::status_lists::acquire_next_dirty` for status lists
//! whose local `committed_version` has advanced past their last
//! published snapshot, builds and signs an `application/statuslist+jwt`
//! via [`crate::domain::status_list::wrapper::build_signed`], and
//! PUTs it to the SWIYU Status Registry through
//! [`StatusRegistryFacade::update_status_list_entry`].
//!
//! The loop runs until its [`CancellationToken`] fires; on shutdown it
//! finishes the in-flight round and exits.

use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use rand_core::RngCore;
use sqlx::PgPool;
use swiyu_registries::common::RegistryError;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::domain::SigningEngine;
use crate::domain::StatusList;
use crate::domain::status_list::wrapper::{BuildError, build_signed};
use crate::persistence::{self, PersistenceError};

use super::backoff::backoff_delay;
use super::registry::StatusRegistryFacade;

/// Default sleep between dispatch-loop polls when no dirty list is
/// runnable. Mirrors `runner::DEFAULT_POLL_INTERVAL`.
pub const DEFAULT_POLL_INTERVAL: StdDuration = StdDuration::from_secs(1);

/// Default lease the publisher holds on an acquired row before another
/// worker may re-acquire it. Plan-credential-management.md leans 30 s.
pub const DEFAULT_LEASE_DURATION_SECS: i64 = 30;

/// Default flat retry interval for terminal failures. Per the plan,
/// terminal failures still require human attention; the long retry
/// keeps the row eligible while observability surfaces it.
pub const DEFAULT_TERMINAL_RETRY_SECS: i64 = 3_600;

pub struct PublisherConfig {
    pub poll_interval: StdDuration,
    pub lease_duration: Duration,
    pub terminal_retry_after: Duration,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            lease_duration: Duration::seconds(DEFAULT_LEASE_DURATION_SECS),
            terminal_retry_after: Duration::seconds(DEFAULT_TERMINAL_RETRY_SECS),
        }
    }
}

/// Publish loop for `status_lists`.
///
/// Construct one per process at startup with shared dependencies
/// (Postgres pool, signing engine, status-registry client), then
/// `tokio::spawn(publisher.run(shutdown))` to launch.
pub struct StatusListPublisher<S, C> {
    pool: PgPool,
    engine: S,
    status_registry: C,
    rng: Box<dyn RngCore + Send + Sync>,
    config: PublisherConfig,
}

impl<S, C> StatusListPublisher<S, C>
where
    S: SigningEngine + 'static,
    C: StatusRegistryFacade + 'static,
{
    pub fn new(
        pool: PgPool,
        engine: S,
        status_registry: C,
        rng: Box<dyn RngCore + Send + Sync>,
    ) -> Self {
        Self {
            pool,
            engine,
            status_registry,
            rng,
            config: PublisherConfig::default(),
        }
    }

    pub fn with_poll_interval(mut self, poll_interval: StdDuration) -> Self {
        self.config.poll_interval = poll_interval;
        self
    }

    pub fn with_lease_duration(mut self, lease_duration: Duration) -> Self {
        self.config.lease_duration = lease_duration;
        self
    }

    pub async fn run(mut self, shutdown: CancellationToken) {
        info!("status-list publisher started");
        loop {
            if shutdown.is_cancelled() {
                break;
            }

            match self.acquire_next().await {
                Ok(Some(list)) => {
                    let list_id = list.id.clone();
                    debug!(list_id = %list_id, "publisher dispatching round");
                    if let Err(e) = self.run_round(list).await {
                        error!(list_id = %list_id, error = %e, "publisher round failed; will retry on next poll");
                    }
                }
                Ok(None) => {
                    tokio::select! {
                        _ = sleep(self.config.poll_interval) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
                Err(e) => {
                    warn!(error = %e, "acquire_next_dirty failed; sleeping before retry");
                    tokio::select! {
                        _ = sleep(self.config.poll_interval) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
            }
        }
        info!("status-list publisher stopped");
    }

    async fn acquire_next(&mut self) -> Result<Option<StatusList>, PersistenceError> {
        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        persistence::status_lists::acquire_next_dirty(
            &mut conn,
            Utc::now(),
            self.config.lease_duration,
        )
        .await
    }

    /// Builds and PUTs the signed JWT for `list`, then records the
    /// outcome on the row. The bitstring snapshot in `list` is the
    /// value at acquire-time; later edits land in subsequent rounds.
    pub async fn run_round(&mut self, list: StatusList) -> Result<(), PublisherError> {
        let mut conn = self.pool.acquire().await?;
        let list_id = list.id.clone();
        let issuer = persistence::issuers::find_by_id(&mut conn, &list.issuer_id)
            .await?
            .ok_or_else(|| {
                PublisherError::Inconsistent(format!(
                    "status_lists row {} references missing issuer {}",
                    list.id, list.issuer_id
                ))
            })?;
        let tenant = persistence::tenants::find_by_id(&mut conn, &issuer.tenant_id)
            .await?
            .ok_or_else(|| {
                PublisherError::Inconsistent(format!(
                    "issuer {} references missing tenant {}",
                    issuer.id, issuer.tenant_id
                ))
            })?;
        let partner_id = tenant.partner_id.clone().ok_or_else(|| {
            PublisherError::Inconsistent(format!(
                "tenant {} has no partner_id; cannot publish",
                tenant.id
            ))
        })?;
        let registry_entry_id = list.registry_entry_id.clone().ok_or_else(|| {
            PublisherError::Inconsistent(format!(
                "status_lists row {} has no registry_entry_id; create_status_list_entry must run first",
                list.id
            ))
        })?;
        let target_version = list.committed_version;

        let now = Utc::now();
        let jwt = match build_signed(&list, &issuer, &self.engine, now).await {
            Ok(s) => s,
            Err(e) => {
                let next = now + self.config.terminal_retry_after;
                error!(list_id = %list_id, error = %e, "publish round build failure (terminal); long retry scheduled");
                persistence::status_lists::record_publish_failure(
                    &mut conn,
                    &list_id,
                    &e.to_string(),
                    next,
                    now,
                )
                .await?;
                return Err(PublisherError::Build(e));
            }
        };

        match self
            .status_registry
            .update_status_list_entry(&partner_id, &registry_entry_id, &jwt)
            .await
        {
            Ok(()) => {
                let won = persistence::status_lists::record_publish_success(
                    &mut conn,
                    &list_id,
                    target_version,
                    now,
                )
                .await?;
                if won {
                    debug!(
                        list_id = %list_id,
                        published_version = target_version,
                        "publish round committed",
                    );
                } else {
                    debug!(
                        list_id = %list_id,
                        published_version = target_version,
                        "publish round was a no-op (concurrent worker advanced past target)",
                    );
                }
                Ok(())
            }
            Err(e) if e.is_retryable() => {
                let attempts = list.publish_attempts.saturating_add(1);
                let delay = backoff_delay(attempts, &mut *self.rng);
                let next =
                    now + Duration::from_std(delay).unwrap_or(self.config.terminal_retry_after);
                warn!(list_id = %list_id, error = %e, attempts, "publish round retryable failure");
                persistence::status_lists::record_publish_failure(
                    &mut conn,
                    &list_id,
                    &e.to_string(),
                    next,
                    now,
                )
                .await?;
                Err(PublisherError::Registry(e))
            }
            Err(e) => {
                let next = now + self.config.terminal_retry_after;
                error!(list_id = %list_id, error = %e, "publish round terminal failure; long retry scheduled");
                persistence::status_lists::record_publish_failure(
                    &mut conn,
                    &list_id,
                    &e.to_string(),
                    next,
                    now,
                )
                .await?;
                Err(PublisherError::Registry(e))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublisherError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("registry: {0}")]
    Registry(RegistryError),
    #[error("wrapper build: {0}")]
    Build(BuildError),
    #[error("inconsistent state: {0}")]
    Inconsistent(String),
}

impl From<sqlx::Error> for PublisherError {
    fn from(e: sqlx::Error) -> Self {
        Self::Persistence(PersistenceError::Db(e))
    }
}
