use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{
    CredentialOfferId, INTEGRITY_HASH_LEN, IssuedCredential, IssuedCredentialId,
    IssuedCredentialState, IssuerId, StatusListId, StatusListIndex, TenantId,
};

use super::PersistenceError;
use super::helpers::{integrity_from, map_database_error};

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
    .bind(credential.id.bare())
    .bind(credential.tenant_id.bare())
    .bind(credential.issuer_id.bare())
    .bind(credential.credential_offer_id.bare())
    .bind(&credential.vct)
    .bind(&credential.holder_key_jkt)
    .bind(credential.status_list_id.bare())
    .bind(credential.status_list_index.value() as i32)
    .bind(credential.state.as_str())
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
    let row = sqlx::query(
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
    .bind(credential_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_credential(&row)).transpose()
}

pub use super::ListPage;

#[derive(Debug, Default)]
pub struct ListFilters {
    pub issuer_id: Option<IssuerId>,
    pub state: Option<IssuedCredentialState>,
    pub vct: Option<String>,
}

/// Inputs to a paginated list query against `issued_credentials`.
///
/// `cursor` carries the `(issued_at, id)` of the last item of the
/// previous page; `None` requests the first page. Ordering is
/// `(issued_at DESC, id DESC)` so newest credentials come first,
/// matching the `issued_credentials_tenant_issuer` index.
#[derive(Debug)]
pub struct ListPageQuery {
    pub filters: ListFilters,
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
    let issuer_filter: Option<&str> = query.filters.issuer_id.as_ref().map(IssuerId::bare);
    let state_filter: Option<&'static str> = query.filters.state.map(IssuedCredentialState::as_str);
    let vct_filter: Option<&str> = query.filters.vct.as_deref();
    let limit_plus_one = i64::from(query.limit) + 1;

    let rows = sqlx::query(
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
    .bind(tenant_id.bare())
    .bind(issuer_filter)
    .bind(state_filter)
    .bind(vct_filter)
    .bind(cursor_issued_at)
    .bind(cursor_credential_id.as_deref())
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let mut credentials: Vec<IssuedCredential> = rows
        .iter()
        .map(row_to_credential)
        .collect::<Result<_, _>>()?;

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
    .bind(credential_id.bare())
    .bind(tenant_id.bare())
    .bind(state.as_str())
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

fn row_to_credential(row: &PgRow) -> Result<IssuedCredential, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let credential_offer_id: String = row.try_get("credential_offer_id")?;
    let vct: String = row.try_get("vct")?;
    let holder_key_jkt: String = row.try_get("holder_key_jkt")?;
    let status_list_id: String = row.try_get("status_list_id")?;
    let status_list_index_raw: i32 = row.try_get("status_list_index")?;
    let state_str: String = row.try_get("state")?;
    let integrity_hash_raw: Vec<u8> = row.try_get("integrity_hash")?;
    let issued_at: DateTime<Utc> = row.try_get("issued_at")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;

    let status_list_index = u32::try_from(status_list_index_raw)
        .ok()
        .and_then(|value| StatusListIndex::try_from(value).ok())
        .ok_or_else(|| PersistenceError::DataIntegrity {
            details: format!(
                "issued_credentials row {id} carries out-of-range status_list_index {status_list_index_raw}"
            ),
        })?;

    if integrity_hash_raw.len() != INTEGRITY_HASH_LEN {
        return Err(PersistenceError::DataIntegrity {
            details: format!(
                "issued_credentials row {id} carries integrity_hash of unexpected length {}",
                integrity_hash_raw.len()
            ),
        });
    }
    let mut integrity_hash = [0u8; INTEGRITY_HASH_LEN];
    integrity_hash.copy_from_slice(&integrity_hash_raw);

    Ok(IssuedCredential {
        id: IssuedCredentialId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        issuer_id: IssuerId::from_bare(issuer_id).map_err(integrity_from)?,
        credential_offer_id: CredentialOfferId::from_bare(credential_offer_id)
            .map_err(integrity_from)?,
        vct,
        holder_key_jkt,
        status_list_id: StatusListId::from_bare(status_list_id).map_err(integrity_from)?,
        status_list_index,
        state: IssuedCredentialState::parse(&state_str).map_err(integrity_from)?,
        integrity_hash,
        issued_at,
        expires_at,
    })
}
