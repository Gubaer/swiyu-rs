use std::env;

const DEFAULT_VAULT_ADDR: &str = "http://127.0.0.1:8200";
const DEFAULT_VAULT_TOKEN: &str = "dev-only-root";

pub fn vault_addr() -> String {
    env::var("VAULT_ADDR").unwrap_or_else(|_| DEFAULT_VAULT_ADDR.to_string())
}

pub fn vault_token() -> String {
    env::var("VAULT_TOKEN").unwrap_or_else(|_| DEFAULT_VAULT_TOKEN.to_string())
}
