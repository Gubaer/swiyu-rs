use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{
    IssuedCredential, IssuedCredentialId, IssuedCredentialState, IssuerId, TenantId,
};

use super::PersistenceError;
use super::helpers::map_database_error;

pub async fn insert(
    conn: &mut PgConnection,
    credential: &IssuedCredential,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO issued_credentials (
            id, tenant_id, issuer_id, credential_offer_id,
            vct, holder_key_jkt,
            status_list_id, status_list_index,
            state, integrity_hash,
            issued_at, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(&credential.id)
    .bind(&credential.tenant_id)
    .bind(&credential.issuer_id)
    .bind(&credential.credential_offer_id)
    .bind(&credential.vct)
    .bind(&credential.holder_key_jkt)
    .bind(&credential.status_list_id)
    .bind(credential.status_list_index)
    .bind(credential.state)
    .bind(&credential.integrity_hash[..])
    .bind(credential.issued_at)
    .bind(credential.expires_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

/// Tenant-scoped lookup. "Wrong tenant" collapses to `Ok(None)` so
/// callers cannot probe across tenants — same discipline as
/// [`crate::persistence::issuers::find_by_id_for_tenant`].
pub async fn find(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_id: &IssuedCredentialId,
) -> Result<Option<IssuedCredential>, PersistenceError> {
    sqlx::query_as::<_, IssuedCredential>(
        r#"
        SELECT id, tenant_id, issuer_id, credential_offer_id,
               vct, holder_key_jkt,
               status_list_id, status_list_index,
               state, integrity_hash,
               issued_at, expires_at
        FROM issued_credentials
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_id)
    .bind(tenant_id)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

pub use super::ListPage;

#[derive(Debug, Default)]
pub struct ListFilters {
    pub issuer_id: Option<IssuerId>,
    pub state: Option<IssuedCredentialState>,
    pub vct: Option<String>,
}

/// Inputs to a paginated list query against `issued_credentials`.
#[derive(Debug)]
pub struct ListPageQuery {
    pub filters: ListFilters,
    /// `(issued_at, id)` of the last item of the previous page; `None`
    /// requests the first page. Ordering is `(issued_at DESC, id DESC)`.
    pub cursor: Option<(DateTime<Utc>, String)>,
    pub limit: u32,
}

pub async fn list(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    query: ListPageQuery,
) -> Result<ListPage<IssuedCredential>, PersistenceError> {
    let (cursor_issued_at, cursor_credential_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let vct_filter: Option<&str> = query.filters.vct.as_deref();
    let limit_plus_one = i64::from(query.limit) + 1;

    let mut credentials = sqlx::query_as::<_, IssuedCredential>(
        r#"
        SELECT id, tenant_id, issuer_id, credential_offer_id,
               vct, holder_key_jkt,
               status_list_id, status_list_index,
               state, integrity_hash,
               issued_at, expires_at
        FROM issued_credentials
        WHERE tenant_id = $1
          AND ($2::TEXT IS NULL OR issuer_id = $2)
          AND ($3::TEXT IS NULL OR state = $3)
          AND ($4::TEXT IS NULL OR vct = $4)
          AND ($5::TIMESTAMPTZ IS NULL OR (issued_at, id) < ($5, $6))
        ORDER BY issued_at DESC, id DESC
        LIMIT $7
        "#,
    )
    .bind(tenant_id)
    .bind(query.filters.issuer_id.as_ref())
    .bind(query.filters.state)
    .bind(vct_filter)
    .bind(cursor_issued_at)
    .bind(cursor_credential_id.as_deref())
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let has_more = credentials.len() as i64 > i64::from(query.limit);
    if has_more {
        credentials.pop();
    }

    Ok(ListPage {
        items: credentials,
        has_more,
    })
}

/// Updates the lifecycle state of an issued credential.
///
/// Returns `PersistenceError::NotFound` when the row does not exist
/// for the given tenant — including the cross-tenant case, which
/// mirrors the lookup discipline of [`find`]. Domain-level
/// state-precondition checks (e.g. "cannot revoke twice") happen at
/// the management layer before this is called; the persistence layer
/// just writes whichever state the caller specified.
pub async fn set_state(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    credential_id: &IssuedCredentialId,
    state: IssuedCredentialState,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE issued_credentials
        SET state = $3
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(credential_id)
    .bind(tenant_id)
    .bind(state)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}
