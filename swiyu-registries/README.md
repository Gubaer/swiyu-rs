# swiyu-registries

Async HTTP clients for the registries operated by [SWIYU](https://www.eid.admin.ch/) — the Swiss eID infrastructure. Pure-data types live in [`swiyu-core`](../swiyu-core); this crate is the one that pulls in `reqwest` and `tokio`.

## What's in the box

Each registry has its own submodule, gated behind a Cargo feature of the same name. Consumers opt in to the ones they need.

| Feature       | Module        | Client                       | What it does                                                                                    |
|---------------|---------------|------------------------------|-------------------------------------------------------------------------------------------------|
| `identifier`  | `identifier`  | `IdentifierRegistryClient`   | Allocate identifier entries, publish DIDLog lines, fetch DIDLogs via the public resolver URL.   |
| `status`      | `status`      | `StatusRegistryClient`       | Create, list, and update status-list entries.                                                   |
| `trust`       | —             | —                            | Reserved for the upcoming Trust Registry client. Not implemented yet.                           |

The `identifier` feature is enabled by default.

```toml
[dependencies]
swiyu-registries = { version = "0.1", features = ["identifier", "status"] }
```

## Design

- **One client per registry.** `IdentifierRegistryClient` and `StatusRegistryClient` are independent; they share only the `common` module (errors, `AccessToken`).
- **Multi-tenant friendly.** Clients hold a `base_url` and a configured `reqwest::Client`. The bearer token is passed per call as an `AccessToken`, not held on the client — one instance can serve every tenant in a process.
- **Hardened defaults.** `new` builds a `reqwest::Client` with HTTPS-only, a 30 s request timeout, a 10 s connect timeout, and an identifying user agent. `with_http` injects a pre-built client for tests against `wiremock` or for sharing a connection pool across registries.
- **Explicit retry classification.** Every fallible call returns `RegistryError`. `RegistryError::is_retryable()` separates transient failures (transport errors, HTTP 429, HTTP 5xx) from permanent ones, so callers can drive backoff loops without re-classifying each variant by hand.
- **Idempotency is documented per method.** For example, `allocate_did` is *not* idempotent (the registry mints a fresh identifier on every POST), while `publish_log_entry` and `fetch_log` are. See the rustdoc on each method for the exact contract.

## Example

```rust
use swiyu_registries::common::AccessToken;
use swiyu_registries::identifier::IdentifierRegistryClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = IdentifierRegistryClient::new(
        "https://identifier-reg-api.trust-infra.swiyu-int.admin.ch".to_string(),
    )?;
    let token = AccessToken::new("…bearer token from your OAuth2 flow…".to_string());

    let allocation = client.allocate_did(&token, "your-partner-id").await?;
    println!("allocated {} at {}", allocation.identifier, allocation.url);

    Ok(())
}
```

## Status

Work in progress. APIs are not yet stable.

| Registry              | End-to-end verified against SWIYU integration environment |
|-----------------------|-----------------------------------------------------------|
| Identifier Registry   | yes                                                       |
| Status Registry       | partial — exercised in unit tests against `wiremock`      |
| Trust Registry        | not implemented                                           |

## License

MIT.
