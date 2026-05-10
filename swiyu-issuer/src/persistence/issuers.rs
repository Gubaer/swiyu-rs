use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};
use uuid::Uuid;

use crate::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};

use super::PersistenceError;
use super::helpers::{integrity_from, map_database_error};

pub async fn exists_for_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<bool, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT 1 AS one
        FROM issuers
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    Ok(row.is_some())
}

/// Loads an issuer by id without scoping to a tenant.
///
/// The wallet-facing OIDC binary has no tenant in its URL, so the
/// lookup needs to fall back on the issuer id alone. The row's
/// `tenant_id` column carries the resolution, which the handler
/// then threads into any tenant-scoped persistence call.
///
/// Returns `Ok(None)` for "no such issuer". Callers in the OIDC
/// binary should respond with the same generic 404 they would for
/// any other unknown wallet-visible identifier.
pub async fn find_by_id(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
) -> Result<Option<Issuer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, did,
               state, description,
               authorized_key_id, authentication_key_id, assertion_key_id,
               display_name, logo_uri, locale,
               created_at
        FROM issuers
        WHERE id = $1
        "#,
    )
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_issuer(&row)).transpose()
}

/// Tenant-scoped variant of [`find_by_id`].
///
/// The management API never resolves an issuer outside the caller's
/// tenant, so the SELECT filters on both columns and "wrong tenant"
/// collapses to the same `Ok(None)` as "no such issuer". Handlers
/// then map either case to a generic 404 — the BA cannot probe for
/// the existence of issuers in other tenants.
pub async fn find_by_id_for_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<Option<Issuer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, did,
               state, description,
               authorized_key_id, authentication_key_id, assertion_key_id,
               display_name, logo_uri, locale,
               created_at
        FROM issuers
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_issuer(&row)).transpose()
}

/// Tenant-scoped variant of [`find_by_id_for_tenant`] that takes a
/// `SELECT … FOR UPDATE` row lock.
///
/// Held for the surrounding transaction's lifetime; serialises
/// concurrent state-transition attempts on the same issuer row so
/// the in-memory state machine in [`Issuer::try_deactivate`] is the
/// sole source of truth without a defence-in-depth SQL guard.
///
/// "Wrong tenant" collapses to `Ok(None)` for the same probing-defence
/// reason as [`find_by_id_for_tenant`].
pub async fn find_by_id_for_update_for_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<Option<Issuer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, did,
               state, description,
               authorized_key_id, authentication_key_id, assertion_key_id,
               display_name, logo_uri, locale,
               created_at
        FROM issuers
        WHERE id = $1 AND tenant_id = $2
        FOR UPDATE
        "#,
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_issuer(&row)).transpose()
}

/// Writes a new `state` value for the named issuer.
///
/// The caller controls the transaction; this helper does not commit.
/// Pairs with [`find_by_id_for_update_for_tenant`] and the in-memory
/// state machine in [`Issuer::try_deactivate`]: load the row under the
/// row lock, run the domain transition, write the result, commit.
///
/// Returns `PersistenceError::NotFound` if no row matches `(issuer_id,
/// tenant_id)`. The caller should have just loaded the row under the
/// `FOR UPDATE` lock, so this only fires on a logic bug.
pub async fn set_state(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    state: IssuerState,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE issuers
        SET state = $1
        WHERE id = $2 AND tenant_id = $3
        "#,
    )
    .bind(state.as_str())
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Outcome of [`swap_key_triple`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapOutcome {
    /// Idempotent re-run: all three key columns already matched the requested triple.
    Already,
    /// First write: at least one key column differed and the UPDATE installed the new values.
    NowSwapped,
}

/// Atomically swaps the three key-id columns of an `Active`
/// issuer, idempotent on re-run.
///
/// The state guard `state = 'active'` rejects swaps against a
/// `Deactivated` issuer or the seeded legacy row (`state IS NULL`):
/// rotation is only meaningful while the issuer is active. The
/// "did anything change" guard in the WHERE clause makes a re-run
/// against a row that already carries the requested triple a 0-row
/// UPDATE; the function then re-reads the row to decide between
/// `Already` and `NotFound`:
///
/// - row exists, state is `active`, all three keys match the
///   requested triple → `SwapOutcome::Already`
/// - row exists in any other state, or is missing, or belongs to
///   a different tenant → `PersistenceError::NotFound`
///
/// Mirrors the lookup discipline of [`find_by_id_for_tenant`]:
/// "wrong tenant" collapses to "not found" so callers cannot probe
/// across tenants.
pub async fn swap_key_triple(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    authorized: &KeyPairId,
    authentication: &KeyPairId,
    assertion: &KeyPairId,
) -> Result<SwapOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE issuers
        SET authorized_key_id = $1,
            authentication_key_id = $2,
            assertion_key_id = $3
        WHERE id = $4 AND tenant_id = $5 AND state = 'active'
          AND (authorized_key_id IS DISTINCT FROM $1
               OR authentication_key_id IS DISTINCT FROM $2
               OR assertion_key_id IS DISTINCT FROM $3)
        "#,
    )
    .bind(authorized.as_uuid())
    .bind(authentication.as_uuid())
    .bind(assertion.as_uuid())
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .execute(&mut *conn)
    .await?;

    if result.rows_affected() == 1 {
        return Ok(SwapOutcome::NowSwapped);
    }

    let row = sqlx::query(
        r#"
        SELECT state, authorized_key_id, authentication_key_id, assertion_key_id
        FROM issuers
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Err(PersistenceError::NotFound);
    };
    let state: Option<String> = row.try_get("state")?;
    let row_authorized: Option<Uuid> = row.try_get("authorized_key_id")?;
    let row_authentication: Option<Uuid> = row.try_get("authentication_key_id")?;
    let row_assertion: Option<Uuid> = row.try_get("assertion_key_id")?;

    let already_matches = state.as_deref() == Some("active")
        && row_authorized.as_ref() == Some(authorized.as_uuid())
        && row_authentication.as_ref() == Some(authentication.as_uuid())
        && row_assertion.as_ref() == Some(assertion.as_uuid());

    if already_matches {
        Ok(SwapOutcome::Already)
    } else {
        Err(PersistenceError::NotFound)
    }
}

pub async fn insert(conn: &mut PgConnection, issuer: &Issuer) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO issuers (
            id, tenant_id, did,
            state, description,
            authorized_key_id, authentication_key_id, assertion_key_id,
            display_name, logo_uri, locale,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(issuer.id.bare())
    .bind(issuer.tenant_id.bare())
    .bind(&issuer.did)
    .bind(issuer.state.map(IssuerState::as_str))
    .bind(issuer.description.as_deref())
    .bind(issuer.authorized_key_id.map(|k| *k.as_uuid()))
    .bind(issuer.authentication_key_id.map(|k| *k.as_uuid()))
    .bind(issuer.assertion_key_id.map(|k| *k.as_uuid()))
    .bind(issuer.display_name.as_deref())
    .bind(issuer.logo_uri.as_deref())
    .bind(issuer.locale.as_deref())
    .bind(issuer.created_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

pub use super::ListPage;

/// Inputs to a paginated list query against `issuers`.
#[derive(Debug)]
pub struct ListPageQuery {
    /// `(created_at, id)` of the last item of the previous page; `None`
    /// requests the first page. Ordering is `(created_at DESC, id DESC)`.
    pub cursor: Option<(DateTime<Utc>, String)>,
    pub limit: u32,
}

/// Paginated list of issuers for a tenant.
///
/// The seeded dev row from migration 0001 is excluded server-side
/// (`state IS NOT NULL`) so it never appears in BA-facing pages.
/// That keeps the list endpoint's contract aligned with the
/// single-fetch endpoint, which 404s the same row.
pub async fn list(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    query: ListPageQuery,
) -> Result<ListPage<Issuer>, PersistenceError> {
    let (cursor_created_at, cursor_issuer_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let limit_plus_one = i64::from(query.limit) + 1;

    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, did,
               state, description,
               authorized_key_id, authentication_key_id, assertion_key_id,
               display_name, logo_uri, locale,
               created_at
        FROM issuers
        WHERE tenant_id = $1
          AND state IS NOT NULL
          AND ($2::TIMESTAMPTZ IS NULL OR (created_at, id) < ($2, $3))
        ORDER BY created_at DESC, id DESC
        LIMIT $4
        "#,
    )
    .bind(tenant_id.bare())
    .bind(cursor_created_at)
    .bind(cursor_issuer_id.as_deref())
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let mut issuers: Vec<Issuer> = rows.iter().map(row_to_issuer).collect::<Result<_, _>>()?;

    let has_more = issuers.len() as i64 > i64::from(query.limit);
    if has_more {
        issuers.pop();
    }

    Ok(ListPage {
        items: issuers,
        has_more,
    })
}

fn row_to_issuer(row: &PgRow) -> Result<Issuer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let did: String = row.try_get("did")?;
    let state: Option<String> = row.try_get("state")?;
    let description: Option<String> = row.try_get("description")?;
    let authorized_key_id: Option<Uuid> = row.try_get("authorized_key_id")?;
    let authentication_key_id: Option<Uuid> = row.try_get("authentication_key_id")?;
    let assertion_key_id: Option<Uuid> = row.try_get("assertion_key_id")?;
    let display_name: Option<String> = row.try_get("display_name")?;
    let logo_uri: Option<String> = row.try_get("logo_uri")?;
    let locale: Option<String> = row.try_get("locale")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;

    Ok(Issuer {
        id: IssuerId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        did,
        state: state
            .map(|s| IssuerState::parse(&s))
            .transpose()
            .map_err(integrity_from)?,
        description,
        authorized_key_id: authorized_key_id.map(KeyPairId::from),
        authentication_key_id: authentication_key_id.map(KeyPairId::from),
        assertion_key_id: assertion_key_id.map(KeyPairId::from),
        display_name,
        logo_uri,
        locale,
        created_at,
    })
}
