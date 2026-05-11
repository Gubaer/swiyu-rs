use crate::domain::TenantId;

const FAMILY_OAUTH2_REFRESH_TOKEN: &str = "oauth2_refresh_token";
const FAMILY_OAUTH2_CLIENT_SECRET: &str = "oauth2_client_secret";

// Hyphen-delimited rather than slash-delimited: Vault Transit's `keys/<name>`
// route uses a name regex that rejects `/`, so `tenant/<id>/<family>` is an
// unroutable key name in Transit. TenantId is bare base58 (no `-`) and
// family names use `_` internally (no `-`), so `tenant-<id>-<family>` parses
// unambiguously.

pub fn oauth2_refresh_token_key_name(tenant_id: &TenantId) -> String {
    format!(
        "tenant-{}-{}",
        tenant_id.bare(),
        FAMILY_OAUTH2_REFRESH_TOKEN
    )
}

pub fn oauth2_client_secret_key_name(tenant_id: &TenantId) -> String {
    format!(
        "tenant-{}-{}",
        tenant_id.bare(),
        FAMILY_OAUTH2_CLIENT_SECRET
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_token_key_name_uses_canonical_layout() {
        let tenant = TenantId::from_bare("9hXq2vRtL8pK7f").unwrap();
        assert_eq!(
            oauth2_refresh_token_key_name(&tenant),
            "tenant-9hXq2vRtL8pK7f-oauth2_refresh_token",
        );
    }

    #[test]
    fn client_secret_key_name_uses_canonical_layout() {
        let tenant = TenantId::from_bare("9hXq2vRtL8pK7f").unwrap();
        assert_eq!(
            oauth2_client_secret_key_name(&tenant),
            "tenant-9hXq2vRtL8pK7f-oauth2_client_secret",
        );
    }

    #[test]
    fn distinct_families_yield_distinct_names() {
        let tenant = TenantId::from_bare("9hXq2vRtL8pK7f").unwrap();
        assert_ne!(
            oauth2_refresh_token_key_name(&tenant),
            oauth2_client_secret_key_name(&tenant),
        );
    }
}
