use sqlx::postgres::PgConnection;

use crate::domain::{IssuerId, TenantId};

use super::PersistenceError;

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
