# swiyu-issuer examples

Standalone smoke programs that drive `swiyu-issuer` end-to-end against a live stack (Postgres + `swiyu-issuer-mgmtapi` + `swiyu-issuer-oidcapi` + the SWIYU integration registries). They are **not** unit or integration tests — they expect real services to be running and they call out to the SWIYU integration backend.

Run any of them with:

```
cargo run --example <name>
```

`cargo build` and `cargo test` do not build examples; they are compiled only on demand.

## What's here

| Example                              | What it exercises                                                                                                  |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `issuer_lifecycle_smoke`             | Issuer DID lifecycle: create, rotate keys, deactivate. Talks to the management API only; verifies each phase against the Identifier Registry. |
| `credential_lifecycle_smoke`         | Full credential issuance flow: management API mints an offer, then a synthetic wallet drives the pre-authorized-code grant against `swiyu-issuer-oidcapi` and receives a credential. |
| `credential_status_lifecycle_smoke`  | Credential issuance plus status-list lifecycle: revoke/suspend bit updates land in the Status Registry as signed `application/statuslist+jwt` documents. |

All three:

- mint a fresh `ApiToken` at startup (TTL 1 h) so orphaned rows expire on their own without manual cleanup,
- own everything they create under the seeded development tenant (`4Mk7yK5pQR7sN3`, inserted by migration `20260430_000001_init.sql`),
- print `=== smoke run PASSED ===` on success and exit non-zero on failure, so they're CI-friendly.

## Environment

The examples read configuration from the process environment. The repo's `.env.example` files document every variable; the ones the examples themselves consume are:

| Variable                  | Required? | Used by                                  | Notes                                                                                  |
|---------------------------|-----------|------------------------------------------|----------------------------------------------------------------------------------------|
| `ISSUER_BASE_URL`         | yes       | all three                                | Management API base, e.g. `http://localhost:8080`. Also used as the OIDC `aud`.        |
| `DATABASE_URL`            | yes       | all three                                | The smokes mint their own `ApiToken` directly in the DB; they don't go through an API. |
| `ISSUER_OIDC_HTTP_URL`    | no        | `credential_lifecycle_smoke`, `credential_status_lifecycle_smoke` | URL the OIDC binary listens on. Defaults to `http://localhost:8081`.                   |
| `LIFECYCLE_TIMEOUT_SECS`  | no        | all three                                | Per-phase timeout. Default: 120.                                                       |
| `LIFECYCLE_POLL_MS`       | no        | all three                                | Polling interval while waiting on async sagas. Default: 1000.                          |
| `SIGNING_ENGINE`          | no        | all three (informational)                | Logged at startup so the run record shows which backend `swiyu-issuer-mgmtapi` is using. The smoke does not act on it — it is `swiyu-issuer-mgmtapi`'s choice.                                                       |
| `RUST_LOG`                | no        | all three                                | Standard `tracing-subscriber` filter. Default: `info`.                                 |

The smokes do not call the registries directly; they observe the management API and the database. Whichever `SWIYU_*` and `OAUTH2_*` variables `swiyu-issuer-mgmtapi` needs must therefore be set in *its* environment, not the smoke's.

## Typical run against the dev compose stack

```
# In one terminal:
docker compose up postgres swiyu-issuer-mgmtapi swiyu-issuer-oidcapi

# In another terminal, with the workspace .env loaded (e.g. via direnv):
cargo run --example issuer_lifecycle_smoke
cargo run --example credential_lifecycle_smoke
cargo run --example credential_status_lifecycle_smoke
```

Each one is independent and idempotent in the sense that it owns the rows it creates; running them in any order, repeatedly, is safe.
