# Vault Transit API — spike notes

Findings from hitting the running dev container (Vault 1.18.5, Transit mounted at `transit/`). Captured fixtures live at `swiyu-issuer/tests/fixtures/vault/`. This file is worktree-local and not committed.

Token used: dev root `dev-only-root` (default from `docker-compose.yml`). All endpoints below assume `Authorization: X-Vault-Token: <token>` on every request and a JSON body where applicable.

## Endpoint summary

| # | Operation | Method + Path | Status | Fixture |
|---|---|---|---|---|
| 1 | Create Ed25519 key | `POST /v1/transit/keys/{id}` body `{"type":"ed25519"}` | 200 | `create_key_ed25519.json` |
| 2 | Create ECDSA P-256 key | `POST /v1/transit/keys/{id}` body `{"type":"ecdsa-p256"}` | 200 | `create_key_ecdsa_p256.json` |
| 3 | Read Ed25519 key | `GET /v1/transit/keys/{id}` | 200 | `get_key_ed25519.json` |
| 4 | Read ECDSA key | `GET /v1/transit/keys/{id}` | 200 | `get_key_ecdsa_p256.json` |
| 5 | Sign Ed25519 (default) | `POST /v1/transit/sign/{id}` body `{"input":"<b64>"}` | 200 | `sign_ed25519.json` |
| 6 | Sign ECDSA prehashed/jws | `POST /v1/transit/sign/{id}` body `{"input":"<b64>","prehashed":true,"hash_algorithm":"sha2-256","marshaling_algorithm":"jws"}` | 200 | `sign_ecdsa_p256.json` |
| 7 | Allow deletion | `POST /v1/transit/keys/{id}/config` body `{"deletion_allowed":true}` | 200 | `config_deletion_allowed.json` |
| 8 | Delete key (allowed) | `DELETE /v1/transit/keys/{id}` | 204 (empty body) | `delete_key_ok.json` (zero-byte) |
| 9 | Read missing key | `GET /v1/transit/keys/{nx}` | 404 | `get_key_not_found.json` |
| 10 | Delete missing key | `DELETE /v1/transit/keys/{nx}` | **400** | `delete_key_not_found.json` |
| 11 | Sign with missing key | `POST /v1/transit/sign/{nx}` | **400** | `sign_key_not_found.json` |
| 12 | Bad token | `POST /v1/transit/sign/{id}` with bogus token | 403 | `sign_unauthorized.json` |
| 13 | Delete without `deletion_allowed=true` | `DELETE /v1/transit/keys/{id}` | 400 | `delete_key_not_allowed.json` |
| 14 | Config on missing key | `POST /v1/transit/keys/{nx}/config` | 400 | `config_key_not_found.json` |

## Surprises vs. the plan

The plan (§3 *Error mapping*) assumed `404 → KeyNotFound` for both `sign` and `delete`. Real Vault behaviour is different and the engine has to read response bodies to disambiguate.

1. **`POST /transit/sign/{nx}` returns 400, not 404.** Body: `{"errors":["signing key not found"]}`. The HTTP status alone does not identify "key missing" — the body string `signing key not found` is the discriminator.
2. **`DELETE /transit/keys/{nx}` returns 400, not 404.** Body: `{"errors":["error deleting policy <id>: could not delete key; not found"]}`. Includes the substring `could not delete key; not found`.
3. **`POST /transit/keys/{id}/config` returns 200 with the full GET-key body** (not 204). The plan's "POST .../config — capture both 200 and the 404 shape" implied 204 + 404. We get 200 + 400.
4. **`DELETE /transit/keys/{id}` on a key with `deletion_allowed=false` returns 400** with `error deleting policy <id>: deletion is not allowed for this key`. This is a programming bug, not a runtime condition we should swallow — the engine *always* sets `deletion_allowed=true` first.

### Implications for `map_error` (revises plan §3)

- `Op::Get`, status 404, body `errors:[]` → `KeyNotFound`.
- `Op::Sign`, status 400, body contains `signing key not found` → `KeyNotFound`. Other 400s → `Backend`.
- `Op::Delete`, status 400, body contains `could not delete key; not found` → swallow (return `Ok(())`). Other 400s → `Backend`. (Allowed by trait: delete is idempotent, so unknown ids are not an error.)
- Any 401/403 → `Backend` (the engine has no recovery; misconfigured token is a deploy issue).
- Any 5xx, network error, JSON parse error → `Backend`.

The substring check is fragile but is what Vault gives us; an integration test pinned to the running container guards against silent message changes.

## Public-key encoding (settles plan §0c)

- **Ed25519** — `data.keys["1"].public_key` is **standard base64** of the raw 32-byte point. Decoded length confirmed: 32 bytes. Example fixture value: `2gc1vkhCCUeNrTVhLA/miCFvEXAFeylMxBdZqwls1HQ=`.
- **ECDSA P-256** — `data.keys["1"].public_key` is **PEM-encoded `SubjectPublicKeyInfo`**, e.g.

  ```
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
  -----END PUBLIC KEY-----
  ```

  Engine normalises to **SEC1 uncompressed** (`0x04 || x || y`, 65 bytes) via `p256::PublicKey::from_public_key_pem(...)?.to_encoded_point(false).as_bytes().to_vec()`, matching what `DevSigningEngine` already produces.

The latest version of any key in our model is always `1` because rotation creates a fresh Vault key under a new UUID (per the spec, "every Vault key in our usage stays at version 1"). So the engine reads `data.keys["1"].public_key` directly — no need to chase `latest_version`.

## Signature envelope decoding (settles plan §3 sign cases)

Both signatures are returned as `data.signature` strings prefixed with `vault:v1:`. The remainder differs by algorithm:

| Algorithm | Prefix | Body encoding | Raw bytes after decode |
|---|---|---|---|
| Ed25519 (default) | `vault:v1:` | **standard base64** (uses `+`, `/`, `=` padding) | 64 (Ed25519 signature) |
| ECDSA P-256 (`marshaling_algorithm=jws`) | `vault:v1:` | **base64url, no padding** (uses `-`, `_`, no `=`) | 64 (raw `r ‖ s`) |

Concrete fixture values (verified):

- Ed25519: `vault:v1:IlKcyf5fLJ19yCrtmtUebOjeM4w+XTzkYP/LasXe2kxy1o08kqR8w/scCS/sEbhX+/h94OHgMwkqII734rRbBA==` → 64 bytes after standard-base64 decode (note `+`, `/`, `==`).
- ECDSA: `vault:v1:nswySSQhbnd95shhno23D43A4zvz9g14fyrC3n-5rRLEe44AtFKkQA1T8jMh9ivZEIl48h_YrORix1w_PEHhWA` → 64 bytes after base64url-no-pad decode (note `-`, `_`, no `=`).

The `r ‖ s` ordering is implicit in the JWS marshalling — same on-the-wire layout the rest of swiyu-issuer expects from `DevSigningEngine`. No further normalisation needed.

### Decode helper sketch

```rust
fn parse_vault_signature(raw: &str, algorithm: KeyAlgorithm) -> Result<Vec<u8>, SigningEngineError> {
    let body = raw.strip_prefix("vault:v1:")
        .ok_or_else(|| backend("missing vault:v1: prefix"))?;
    let bytes = match algorithm {
        KeyAlgorithm::Ed25519   => BASE64_STANDARD.decode(body),
        KeyAlgorithm::EcdsaP256 => BASE64_URL_SAFE_NO_PAD.decode(body),
    }.map_err(|e| backend(&format!("base64: {e}")))?;
    if bytes.len() != 64 {
        return Err(backend(&format!("unexpected signature length {}", bytes.len())));
    }
    Ok(bytes)
}
```

(The `base64` 0.22 crate is already in `[dependencies]`. Both `BASE64_STANDARD` and `BASE64_URL_SAFE_NO_PAD` are in the prelude.)

## Sign request body — base64 flavour for `input`

Vault's API doc says the sign endpoint expects `"input"` as base64-encoded bytes. The container accepted **standard base64** for both the Ed25519 message (`hello swiyu`) and the ECDSA digest (32 bytes of `0xa5`). I did not test base64url for `input`; standard base64 is what we send and what works.

## JSON shapes (paths the engine reads)

For each successful response the engine touches the following fields:

- Create / Read key: `data.type` (string: `"ed25519"` or `"ecdsa-p256"`) and `data.keys["1"].public_key` (string per encoding rules above).
- Sign: `data.signature` (string, `vault:v1:` prefix).
- Update config: response body is ignored (engine just checks status).
- Delete: response body is empty (204) or, on the 400-not-found case, is read for the substring match.

## Misc operational notes

- Vault dev mode wipes state on every container restart. Fixtures captured here are stable shapes, but the example bytes shift on each `docker compose down -v` ; tests that depend on exact bytes (e.g. cross-engine equivalence) need a fresh capture or an in-test generation step.
- `request_id`, `lease_id`, `creation_time`, and most metadata in the GET body change on every call; the engine ignores everything except `type` and `keys["1"].public_key`. Fixture parsing tests should not pin those volatile fields.
- `latest_version` is always `1` for keys we create (we never call rotate). Engine assumes `keys["1"]` exists.
