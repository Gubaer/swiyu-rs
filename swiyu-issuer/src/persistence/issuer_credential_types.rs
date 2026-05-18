use sqlx::postgres::PgConnection;

use crate::domain::{CredentialTypeId, IssuerCredentialTypeAssignment, IssuerId};

use super::PersistenceError;
use super::helpers::map_database_error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOutcome {
    AlreadyAssigned,
    NowAssigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnassignOutcome {
    NotAssigned,
    NowUnassigned,
}

/// Inserts an `issuer_credential_types` row, idempotent on the
/// primary key `(issuer_id, credential_type_id)`.
///
/// The cross-tenant ownership check — *both* the issuer and the
/// credential type belong to the same tenant — is the caller's
/// responsibility; this helper relies on the FKs to `issuers` and
/// `credential_types` for referential integrity.
pub async fn assign(
    conn: &mut PgConnection,
    assignment: &IssuerCredentialTypeAssignment,
) -> Result<AssignOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        INSERT INTO issuer_credential_types
            (issuer_id, credential_type_id, tenant_id, assigned_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (issuer_id, credential_type_id) DO NOTHING
        "#,
    )
    .bind(&assignment.issuer_id)
    .bind(&assignment.credential_type_id)
    .bind(&assignment.tenant_id)
    .bind(assignment.assigned_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        Ok(AssignOutcome::AlreadyAssigned)
    } else {
        Ok(AssignOutcome::NowAssigned)
    }
}

/// Idempotent: deleting an absent row returns
/// [`UnassignOutcome::NotAssigned`] rather than an error.
pub async fn unassign(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
    credential_type_id: &CredentialTypeId,
) -> Result<UnassignOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        DELETE FROM issuer_credential_types
        WHERE issuer_id = $1 AND credential_type_id = $2
        "#,
    )
    .bind(issuer_id)
    .bind(credential_type_id)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        Ok(UnassignOutcome::NotAssigned)
    } else {
        Ok(UnassignOutcome::NowUnassigned)
    }
}

/// Returns link rows only; callers join `credential_types` separately
/// when they need the structured fields.
pub async fn list_by_issuer(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
) -> Result<Vec<IssuerCredentialTypeAssignment>, PersistenceError> {
    let rows = sqlx::query_as::<_, IssuerCredentialTypeAssignment>(
        r#"
        SELECT issuer_id, credential_type_id, tenant_id, assigned_at
        FROM issuer_credential_types
        WHERE issuer_id = $1
        ORDER BY assigned_at DESC, credential_type_id DESC
        "#,
    )
    .bind(issuer_id)
    .fetch_all(conn)
    .await?;
    Ok(rows)
}

pub async fn list_by_credential_type(
    conn: &mut PgConnection,
    credential_type_id: &CredentialTypeId,
) -> Result<Vec<IssuerCredentialTypeAssignment>, PersistenceError> {
    let rows = sqlx::query_as::<_, IssuerCredentialTypeAssignment>(
        r#"
        SELECT issuer_id, credential_type_id, tenant_id, assigned_at
        FROM issuer_credential_types
        WHERE credential_type_id = $1
        ORDER BY assigned_at DESC, issuer_id DESC
        "#,
    )
    .bind(credential_type_id)
    .fetch_all(conn)
    .await?;
    Ok(rows)
}

/// Cheaper than [`list_by_issuer`] when only the predicate is needed.
pub async fn is_assigned(
    conn: &mut PgConnection,
    issuer_id: &IssuerId,
    credential_type_id: &CredentialTypeId,
) -> Result<bool, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT 1 AS one
        FROM issuer_credential_types
        WHERE issuer_id = $1 AND credential_type_id = $2
        "#,
    )
    .bind(issuer_id)
    .bind(credential_type_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.is_some())
}
