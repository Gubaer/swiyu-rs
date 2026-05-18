use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, TenantId};

use super::PersistenceError;
use super::helpers::map_database_error;

pub async fn insert(
    conn: &mut PgConnection,
    offer: &CredentialOffer,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO credential_offers (
            id, tenant_id, issuer_id, vct, credential_type_id,
            claims, state, pre_auth_code, expires_at, created_at,
            issued_at, cancelled_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(&offer.id)
    .bind(&offer.tenant_id)
    .bind(&offer.issuer_id)
    .bind(&offer.vct)
    .bind(offer.credential_type_id.as_ref())
    .bind(&offer.claims)
    .bind(offer.state)
    .bind(offer.pre_auth_code.as_ref())
    .bind(offer.expires_at)
    .bind(offer.created_at)
    .bind(offer.issued_at)
    .bind(offer.cancelled_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    Ok(())
}

pub async fn find_by_id(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
) -> Result<CredentialOffer, PersistenceError> {
    sqlx::query_as::<_, CredentialOffer>(
        r#"
        SELECT id, tenant_id, issuer_id, vct, credential_type_id,
               claims, state, pre_auth_code, expires_at, created_at,
               issued_at, cancelled_at
        FROM credential_offers
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
        "#,
    )
    .bind(offer_id)
    .bind(tenant_id)
    .bind(issuer_id)
    .fetch_optional(conn)
    .await?
    .ok_or(PersistenceError::NotFound)
}

pub use super::ListPage;

/// Inputs to a paginated list query against `credential_offers`.
///
/// `cursor` carries the `(created_at, id)` of the last item of the
/// previous page; `None` requests the first page. `state_filter` is
/// the *observed* state — `expired` matches stored-`pending` rows
/// past their `expires_at`, and `pending` matches stored-`pending`
/// rows still within their `expires_at`. `now` is the reference time
/// used for the expiry projection; pass the same instant the handler
/// uses to render the response so the SQL filter and the observed
/// state in each row agree.
#[derive(Debug)]
pub struct ListPageQuery {
    pub state_filter: Option<CredentialOfferState>,
    pub cursor: Option<(DateTime<Utc>, String)>,
    pub limit: u32,
    pub now: DateTime<Utc>,
}

pub async fn list(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    query: ListPageQuery,
) -> Result<ListPage<CredentialOffer>, PersistenceError> {
    let (cursor_created_at, cursor_offer_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let limit_plus_one = i64::from(query.limit) + 1;

    let mut offers = sqlx::query_as::<_, CredentialOffer>(
        r#"
        SELECT id, tenant_id, issuer_id, vct, credential_type_id,
               claims, state, pre_auth_code, expires_at, created_at,
               issued_at, cancelled_at
        FROM credential_offers
        WHERE tenant_id = $1
          AND issuer_id = $2
          AND ($3::TIMESTAMPTZ IS NULL OR (created_at, id) < ($3, $4))
          AND (
                $5::TEXT IS NULL
                OR ($5 = 'pending'   AND state = 'pending' AND expires_at >  $6)
                OR ($5 = 'expired'   AND state = 'pending' AND expires_at <= $6)
                OR ($5 = 'issued'    AND state = 'issued')
                OR ($5 = 'cancelled' AND state = 'cancelled')
              )
        ORDER BY created_at DESC, id DESC
        LIMIT $7
        "#,
    )
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(cursor_created_at)
    .bind(cursor_offer_id.as_deref())
    .bind(query.state_filter)
    .bind(query.now)
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let has_more = offers.len() as i64 > i64::from(query.limit);
    if has_more {
        offers.pop();
    }

    Ok(ListPage {
        items: offers,
        has_more,
    })
}

/// Persists a `Pending` → `Cancelled` transition for the named offer.
///
/// Caller is responsible for loading the offer, running domain-level
/// state-machine checks, and supplying `cancelled_at`. The SQL guard
/// `state = 'pending'` is defence in depth: it prevents a concurrent
/// [`set_issued_state`][super::oidc::credential_offers::set_issued_state]
/// from being clobbered by a cancel that loaded a stale row. A 0-row
/// update is reported as [`NotFound`][PersistenceError::NotFound];
/// it means the offer either does not exist for this tenant/issuer
/// or has already left `Pending`.
pub async fn cancel(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
    cancelled_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_offers
        SET state = 'cancelled',
            cancelled_at = $4,
            pre_auth_code = NULL
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
              AND state = 'pending'
        "#,
    )
    .bind(offer_id)
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(cancelled_at)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Bulk-cancels every `Pending` offer for the named issuer.
///
/// Used by the deactivate-issuer saga's terminal local step, which
/// runs in the same transaction that flips the issuer row to
/// `Deactivated`. Already-`issued`, already-`cancelled`, and
/// already-`expired` (i.e. stored-`pending` past `expires_at`)
/// offers are left alone. The expiry projection from [`list`] is
/// deliberately *not* applied here: an offer that is observably
/// `Expired` but stored as `Pending` still has an active
/// `pre_auth_code` row, and zeroing it out alongside the bulk cancel
/// is desirable rather than a bug.
///
/// Returns the number of rows that flipped to `cancelled` so the
/// worker can log/observe the count. A zero return is normal — it
/// means the issuer had no pending offers, which is the common case
/// when the BA has already drained outstanding work before
/// requesting deactivation.
///
/// Tenant-scoping is defence in depth: the issuer_id alone is
/// enough to locate the rows (`issuers.id` is globally unique and
/// `credential_offers.issuer_id` references it), but filtering on
/// both columns matches the rest of this module's query discipline
/// and keeps the call safe even if a future table layout drops the
/// FK.
pub async fn cancel_all_pending_for_issuer(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    cancelled_at: DateTime<Utc>,
) -> Result<u64, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_offers
        SET state = 'cancelled',
            cancelled_at = $3,
            pre_auth_code = NULL
        WHERE tenant_id = $1 AND issuer_id = $2
              AND state = 'pending'
        "#,
    )
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(cancelled_at)
    .execute(conn)
    .await?;

    Ok(result.rows_affected())
}
