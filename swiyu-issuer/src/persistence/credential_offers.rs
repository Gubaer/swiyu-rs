use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCodeHash, TenantId,
};

use super::PersistenceError;
use super::helpers::{integrity_from, map_database_error};

pub async fn insert(
    conn: &mut PgConnection,
    offer: &CredentialOffer,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO credential_offers (
            id, tenant_id, issuer_id, vct, claims, state,
            pre_auth_code_hash, expires_at, created_at,
            issued_at, cancelled_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(offer.id.bare())
    .bind(offer.tenant_id.bare())
    .bind(offer.issuer_id.bare())
    .bind(&offer.vct)
    .bind(&offer.claims)
    .bind(offer.state.as_str())
    .bind(offer.pre_auth_code_hash.as_str())
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
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, issuer_id, vct, claims, state,
               pre_auth_code_hash, expires_at, created_at,
               issued_at, cancelled_at
        FROM credential_offers
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
        "#,
    )
    .bind(offer_id.bare())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?;

    match row {
        None => Err(PersistenceError::NotFound),
        Some(row) => row_to_offer(&row),
    }
}

/// One page of credential offers plus a flag indicating whether more
/// rows remain past the current page.
///
/// The flag is computed by fetching `limit + 1` rows internally and
/// dropping the surplus before returning. Callers do not need to add
/// the `+ 1` themselves.
#[derive(Debug)]
pub struct ListPage {
    pub items: Vec<CredentialOffer>,
    pub has_more: bool,
}

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
) -> Result<ListPage, PersistenceError> {
    let (cursor_created_at, cursor_offer_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let state_filter_str: Option<&'static str> = query.state_filter.map(|s| s.as_str());
    let limit_plus_one = i64::from(query.limit) + 1;

    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, issuer_id, vct, claims, state,
               pre_auth_code_hash, expires_at, created_at,
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
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .bind(cursor_created_at)
    .bind(cursor_offer_id.as_deref())
    .bind(state_filter_str)
    .bind(query.now)
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let mut offers: Vec<CredentialOffer> =
        rows.iter().map(row_to_offer).collect::<Result<_, _>>()?;

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
/// `mark_issued` (once that lands) from being clobbered by a cancel
/// that loaded a stale row. A 0-row update is reported as
/// `PersistenceError::NotFound`; it means the offer either does not
/// exist for this tenant/issuer or has already left `Pending`.
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
        SET state = 'cancelled', cancelled_at = $4
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
              AND state = 'pending'
        "#,
    )
    .bind(offer_id.bare())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .bind(cancelled_at)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

fn row_to_offer(row: &PgRow) -> Result<CredentialOffer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let vct: String = row.try_get("vct")?;
    let claims: Value = row.try_get("claims")?;
    let state_str: String = row.try_get("state")?;
    let pre_auth_code_hash: String = row.try_get("pre_auth_code_hash")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let issued_at: Option<DateTime<Utc>> = row.try_get("issued_at")?;
    let cancelled_at: Option<DateTime<Utc>> = row.try_get("cancelled_at")?;

    Ok(CredentialOffer {
        id: CredentialOfferId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        issuer_id: IssuerId::from_bare(issuer_id).map_err(integrity_from)?,
        vct,
        claims,
        state: CredentialOfferState::parse(&state_str).map_err(integrity_from)?,
        pre_auth_code_hash: PreAuthCodeHash::from_stored(pre_auth_code_hash),
        expires_at,
        created_at,
        issued_at,
        cancelled_at,
    })
}
