# Plan: VaultSigningEngine

Implementation plan for the `VaultSigningEngine` backend described in `impl-key-management.md`. This file is the working plan; it is not the spec. Once the work lands, the substance moves into `impl-key-management.md` and this file is deleted.

## 0. Decisions (locked)

These shape the rest of the work and are no longer open.

### 0a. HTTP client: hand-rolled with `reqwest`

Five Transit endpoints, all well-defined. Hand-rolling keeps the dependency surface minimal and gives us full control over error mapping. `vaultrs` would save ~300 lines of HTTP plumbing but introduces policies (timeouts, retries, error shapes) we'd then have to work around.

### 0b. Dispatch: enum, not `Box<dyn SigningEngine>`

The set of backends is closed (dev / vault / hsm) and chosen once at startup. Enum dispatch reads cleanly, avoids the `async-trait` / `trait_variant` macro dependency, and gives exhaustiveness checking when we add backends. Resolves open question #1 from `impl-key-management.md`.

### 0c. ECDSA P-256 public-key normalisation: SEC1 uncompressed

Vault returns ECDSA public keys as PEM-encoded `SubjectPublicKeyInfo`. The trait contract says `RawPublicKey::bytes` is single-shape per algorithm; both backends must agree. The engine normalises to SEC1 uncompressed (`0x04 || x || y`, 65 bytes) — matching what `DevSigningEngine` already produces. Implementation: `p256::PublicKey::from_public_key_pem(...)` then `.to_encoded_point(false).as_bytes().to_vec()`. No new deps (`p256` is already in for the dev engine). The byte-shape rule is then promoted into the trait section of the spec, not buried in a backend.

## 1. Spike: confirm Vault response shapes — **done**

The spike has been run against the dev container (Vault 1.18.5). Fixtures captured at `swiyu-issuer/tests/fixtures/vault/`; full write-up at `swiyu-issuer/specs/notes-vault-api.md`. Findings settle the open shape questions and revise the error-mapping section below.

Endpoints captured:

- `POST /v1/transit/keys/{uuid}` — both `type=ed25519` and `type=ecdsa-p256` → 200.
- `GET /v1/transit/keys/{uuid}` — both algorithms → 200. Ed25519 public key is standard base64 of 32 raw bytes at `data.keys["1"].public_key`. ECDSA public key is PEM `SubjectPublicKeyInfo` at the same path.
- `POST /v1/transit/sign/{uuid}` — Ed25519 (default) → 200. Signature at `data.signature`, prefixed `vault:v1:` + standard base64 → 64 raw bytes.
- `POST /v1/transit/sign/{uuid}` — ECDSA P-256 with `prehashed=true`, `hash_algorithm=sha2-256`, `marshaling_algorithm=jws` → 200. Signature `vault:v1:` + base64url-no-pad → 64 raw bytes (`r ‖ s`).
- `POST /v1/transit/keys/{uuid}/config` with `deletion_allowed=true` → 200 (returns the full key body, not 204).
- `DELETE /v1/transit/keys/{uuid}` (allowed) → 204 empty body.
- `GET /v1/transit/keys/{nx}` → 404, body `{"errors":[]}`.
- `POST /v1/transit/sign/{nx}` → **400** (not 404), body `{"errors":["signing key not found"]}`.
- `DELETE /v1/transit/keys/{nx}` → **400** (not 404), body `{"errors":["error deleting policy <id>: could not delete key; not found"]}`.
- `POST /v1/transit/keys/{nx}/config` → 400, body `{"errors":["no existing key named <id> could be found"]}`.
- `DELETE /v1/transit/keys/{id}` without `deletion_allowed=true` → 400, body `{"errors":["error deleting policy <id>: deletion is not allowed for this key"]}`. Engine never hits this path because it always sets `deletion_allowed=true` first.
- Bogus token on any endpoint → 403, body `{"errors":["2 errors occurred:\n\t* permission denied\n\t* invalid token\n\n"]}`.

Implication: HTTP status alone does not identify "key missing" for `sign` or `delete`. The engine must read response bodies for those two cases.

## 2. Configuration

Add a `VaultSigningEngineConfig` struct:

```rust
pub struct VaultSigningEngineConfig {
    pub address: Url,                   // VAULT_ADDR
    pub token: SecretString,            // VAULT_TOKEN
    pub transit_path: String,           // default "transit"
    pub request_timeout: Duration,      // default 5s
}
```

Read from env in the binary: `VAULT_ADDR`, `VAULT_TOKEN`, optional `VAULT_TRANSIT_PATH`, optional `VAULT_REQUEST_TIMEOUT_SECS`. Add the missing entries to `.env.example`. Use `secrecy::SecretString` for the token to avoid accidental logging (small new dep, justified — tokens leaking into logs is a recurring real-world failure mode).

Deferred (engine-internal per the spec, not surfaced in the trait): AppRole / Kubernetes auth, token renewal, mTLS, namespaces.

## 3. Engine implementation

Create `swiyu-issuer/src/domain/signing_engine/vault.rs` mirroring the structure of `dev.rs` for symmetry. One `reqwest::Client` is built once in `VaultSigningEngine::new` and shared across all calls.

### `generate_keypair(role)`

1. Pick algorithm via `KeyAlgorithm::for_role(role)`.
2. `let id = KeyPairId::generate();`
3. `POST /v1/{transit_path}/keys/{id}` with body `{"type": "ed25519" | "ecdsa-p256"}`.
4. `GET /v1/{transit_path}/keys/{id}` and parse the public key (per phase 1's findings, normalised to SEC1 uncompressed for ECDSA, raw 32 bytes for Ed25519).
5. Insert `(id → algorithm)` into the in-memory algorithm cache (see `sign`).
6. Return `GeneratedKeyPair`.

### `get_public_key(id)`

`GET /v1/{transit_path}/keys/{id}`, decode the public key, infer algorithm from the response's `type` field. Map 404 → `KeyNotFound`. Populate the algorithm cache as a side-effect.

### `sign(id, input)`

The trait pre-validates ECDSA input length but the engine itself needs to know the algorithm before crafting the request. Two options: fetch on every call, or cache. We cache: a `parking_lot::RwLock<HashMap<KeyPairId, KeyAlgorithm>>` populated on first lookup of any id. Eviction on `delete_keypair`. The cache is best-effort — a miss falls through to a `GET /v1/{transit_path}/keys/{id}` to learn the algorithm, then caches.

- Ed25519: `POST /v1/{transit_path}/sign/{id}` with `{"input": base64(input)}`. Decode `data.signature` as `vault:v1:<standard-base64>` → 64 raw bytes.
- ECDSA P-256: validate `input.len() == 32` (`InvalidInputLength` otherwise) → `POST /v1/{transit_path}/sign/{id}` with `{"input": base64(input), "prehashed": true, "hash_algorithm": "sha2-256", "marshaling_algorithm": "jws"}`. Decode `data.signature` as `vault:v1:<base64url-no-padding>` → 64 raw bytes (`r || s`).

Vault returns **400 with body `{"errors":["signing key not found"]}`** when the key is missing, not 404. Map that body shape → `KeyNotFound`; other 400s → `Backend`.

### `delete_keypair(id)`

- `POST /v1/{transit_path}/keys/{id}/config` with `{"deletion_allowed": true}` — swallow 400 with body containing `no existing key named` (key already gone). Other 400s → `Backend`.
- `DELETE /v1/{transit_path}/keys/{id}` — swallow 400 with body containing `could not delete key; not found`. Other 400s → `Backend`.
- Drop from the algorithm cache.

Idempotent per the trait contract. Vault returns 400 (not 404) for missing keys on both endpoints, so the engine discriminates on the body string. The substring match is fragile but is what Vault gives us; the integration test suite catches any wording change.

### Error mapping

Concentrate all status-to-error mapping in one helper. Network errors and JSON parse failures map to `Backend`. Resist adding finer-grained variants to `SigningEngineError` until concrete failure modes show up in real use — the spec is explicit about that.

The spike showed Vault uses 400, not 404, for "key missing" on `sign` and `delete`, so the helper has to inspect the body string for those operations. `Get` is the only operation that returns a clean 404 for missing keys.

```rust
fn map_error(status: StatusCode, body: &str, id: KeyPairId, op: Op) -> SigningEngineError {
    match (op, status.as_u16()) {
        (Op::Get, 404) => SigningEngineError::KeyNotFound(id),
        (Op::Sign, 400) if body.contains("signing key not found") => {
            SigningEngineError::KeyNotFound(id)
        }
        // Delete-related "already gone" cases are swallowed by the caller before
        // they reach this helper; they never produce a SigningEngineError.
        _ => SigningEngineError::Backend(format!("vault {}: {}", status, body).into()),
    }
}
```

The two delete-path "not found" body substrings (`no existing key named` for the config update, `could not delete key; not found` for the delete itself) are matched at the call site in `delete_keypair`, not here, so this helper stays focused on the `KeyNotFound` cases that actually surface to callers.

### Retry / backoff

Out of scope for this round. The trait surface stays the same when we add it later (interceptor at the `reqwest::Client` layer or a thin wrapper inside the engine). A single attempt with the configured `request_timeout` is the v1 behaviour.

## 4. Tests

### Unit tests (in-file `#[cfg(test)]`)

- Signature envelope parsing: `vault:v1:<base64>` → 64 bytes, both standard base64 (Ed25519) and base64url-no-padding (ECDSA + jws marshalling).
- ECDSA public-key conversion: PEM SPKI input → SEC1 uncompressed output, byte-exact against a known vector.
- Error mapping: `Get` 404 → `KeyNotFound`; `Sign` 400 with body `signing key not found` → `KeyNotFound`; `Sign` 400 with other body → `Backend`; `delete_keypair` 400 with `could not delete key; not found` → `Ok(())`; `delete_keypair` 400 with `no existing key named` on the config update → `Ok(())`; 403 / 500 / network → `Backend`.

These run against the captured fixture JSON; no Vault needed.

### Integration tests (`swiyu-issuer/tests/vault_signing_engine.rs`)

`#[ignore]` by default; run with `cargo test --test vault_signing_engine -- --ignored` once the Vault container is up. Coverage:

- Roundtrips for both algorithms: generate → `get_public_key` → sign → verify locally with `ed25519-dalek` / `p256` → delete → subsequent `sign` returns `KeyNotFound`.
- Variable-length Ed25519 input (32, 64, 100 bytes) — guards against accidentally pre-hashing.
- ECDSA: 31-byte input → `InvalidInputLength`; 32-byte input → success.
- `delete_keypair` of an unknown id → `Ok(())`; of an existing id followed by a second delete → `Ok(())`.

CI runs `docker compose up -d vault vault-init`, waits for the `vault` healthcheck, runs the integration tests, then `docker compose down -v`. Mirror whatever pattern the Postgres integration tests use (or establish one if there isn't one yet).

### Cross-engine equivalence test (nice-to-have)

A small test that exercises both `DevSigningEngine` and `VaultSigningEngine` through the same `SigningEngine` trait calls and asserts the public-key shape and signature shape match the format the DIDLog layer expects. Catches drift between dev and vault paths early.

## 5. Wiring into the binary

Add the dispatch enum:

```rust
pub enum AnySigningEngine {
    Dev(DevSigningEngine),
    Vault(VaultSigningEngine),
}
```

Each trait method is `match self { ... }`. The `Hsm(HsmSigningEngine)` variant slots in later under the same enum.

Backend selection from env: `SIGNING_ENGINE=dev` (default) or `SIGNING_ENGINE=vault`. Document in `.env.example`. Read once at startup; the engine is held in an `Arc<AnySigningEngine>` and shared across handlers.

## 6. Spec updates

After implementation lands, update `impl-key-management.md`:

- Mark `VaultSigningEngine` as **shipped** rather than "if/when implemented". The maturity-level intent does not change — only the implementation status.
- Resolve open question 1 (dispatch) → enum dispatch with the rationale from §0b.
- Promote the public-key normalisation rule (engines return SEC1 uncompressed for ECDSA, raw 32 bytes for Ed25519) into the trait section, not buried in a backend.
- Capture the Vault signature-envelope decoding rules (`vault:v1:` prefix, base64 vs base64url depending on algorithm) as a short paragraph under the Vault subsection — they are non-obvious and the next reader will want them.
- Capture the "key missing" mapping rules: `GET` returns 404 cleanly, but `sign` and `delete` return 400 with discriminating body strings (`signing key not found`, `could not delete key; not found`, `no existing key named`). Note that the engine matches on body substring; the integration tests guard against silent wording changes.
- Replace the network-failure subsection's "to be specified when implementation begins" with the actual v1 behaviour: single attempt, configurable timeout (default 5s), all failures map to `Backend`, retry/backoff deferred.
- Delete this plan file once the spec carries the substance. The companion `notes-vault-api.md` either folds into the spec or is deleted; do not leave a freestanding spike notes file in `specs/` long-term.

## 7. Out of scope for this round

State explicitly so future readers don't think we forgot:

- AppRole / Kubernetes / JWT auth methods.
- Token renewal and lease management.
- TLS verification configuration (needed once the dev compose is no longer plain HTTP).
- Retry / backoff and circuit-breaking.
- Vault namespace support (Enterprise feature).
- Open question #2 in the spec (typed `RawPublicKey` enum) — touching this means changing the trait, broader than `VaultSigningEngine`. Better as its own task once the DIDLog wiring shows what's actually needed.

## 8. Suggested commit sequence

Roughly one PR-sized chunk, split for reviewability:

1. Spike fixtures + notes (no production code). **Done** — fixtures at `swiyu-issuer/tests/fixtures/vault/`, notes at `swiyu-issuer/specs/notes-vault-api.md`.
2. `VaultSigningEngineConfig` + skeleton struct, no methods yet.
3. `generate_keypair` + `get_public_key` + their unit tests.
4. `sign` (both algorithms) + unit tests.
5. `delete_keypair` + unit tests.
6. Integration test file (ignored by default) + CI step.
7. `AnySigningEngine` enum + backend selection in the binary.
8. Spec updates and deletion of this plan file.

Estimated effort: ~1.5–2 days end to end, most of which is the integration-test setup and the public-key encoding fiddle.
