// Tests that construct a `Worker` or `StatusListPublisher` each
// include `tests/common/mod.rs` directly via `#[path]`. They are
// compiled as standalone Cargo test targets only, not as submodules
// of this aggregator, to avoid the `clippy::duplicate_mod` lint that
// fires when the same `common/mod.rs` is loaded multiple times into
// one compilation unit.
mod api_create_issuer;
mod api_deactivate_issuer;
mod api_get_issuer;
mod api_get_operation_task;
mod api_list_issuers;
mod api_management_credential_types;
mod api_management_issued_credentials;
mod api_management_issued_credentials_get;
mod api_oidc_credential;
mod api_rotate_keys;
mod credential_offers_persistence;
mod credential_types_persistence;
mod dev_signing_engine;
mod dispatch;
mod issued_credentials_persistence;
mod issuer_credential_types_persistence;
mod issuers_persistence;
mod mark_deactivated;
mod operation_tasks_persistence;
mod persist_issuer;
mod provision_status_list;
mod status_lists_persistence;
mod swap_keys;
mod tenants_persistence;
mod vault_signing_engine;
