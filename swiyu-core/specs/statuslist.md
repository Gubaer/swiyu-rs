This is the specification for the `statuslist` module in this repository.

The `statuslist` module provides decoding and slot-lookup primitives for status lists used by SD-JWT VCs in the SWIYU ecosystem (`SwissTokenStatusList-1.0`, layered on the [IETF Token Status List][ietf-tsl] draft).

The module is **I/O-free**. Fetching a status-list JWT and verifying its signature happen in the consuming application; this module only handles the wire-format decode (`payload.status_list`) and the slot-value semantics. That separation lets multiple callers — a CLI, a verifier service, a wallet — share the same parsing logic.

# Concepts

Two distinct types:

* **`StatusListPointer`** — the small object embedded at `payload.status.status_list` of an SD-JWT VC. Tells a verifier which list to fetch and which slot within it represents the credential. Fields: `type`, `idx`, `uri`.
* **`StatusList`** — the decoded, decompressed bitstring carried by the status-list JWT itself. Constructed from the JWT's `payload.status_list` object; queried by 0-based slot index.

Slot values are interpreted via **`StatusValue`**:

| Raw bits | `StatusValue` | Meaning |
|---|---|---|
| `0` | `Valid` | The credential is currently valid. |
| `1` | `Revoked` | The credential has been revoked. |
| `2` (2-bit only) | `Suspended` | Temporarily suspended. |
| `3` (2-bit) or other | `Reserved(u8)` | Reserved or application-defined; treat conservatively. |

# Requirements

## Module placement

* The module must live in `swiyu-core` as `statuslist` (file: `src/statuslist/mod.rs`).
* The module must be re-exported from `lib.rs` so it is reachable as `swiyu_core::statuslist`.

## Public types

* `StatusListPointer` — a public struct with private fields `type_`, `idx`, `uri`. Provide `new`, getters (`type_()`, `idx()`, `uri()`), and the conversion traits `TryFrom<&Value>` (parse) and `From<&StatusListPointer> for Value` (serialise).
* `StatusList` — a public struct with private fields `bits` and `bytes`. Provide `new`, `from_raw`, `bits()`, `as_bytes()`, `len()`, `is_empty()`, `value_at()`, `set_at()`, plus the conversion traits `TryFrom<&Value>` (parse) and `From<&StatusList> for Value` (serialise).
* `StatusValue` — a public enum with variants `Valid`, `Revoked`, `Suspended`, `Reserved(u8)`. Provide `is_valid()`, plus the width-agnostic numeric conversions `From<StatusValue> for u8` (`Valid=0`, `Revoked=1`, `Suspended=2`, `Reserved(n)=n`) and `From<u8> for StatusValue` (`0/1/2` map to the named variants, anything else falls into `Reserved`). The width-aware encoder used by `StatusList::set_at` (which fails when a value doesn't fit in `bits`) is an internal helper.
* `StatusListJwtHeader` — a public struct with private fields `alg`, `typ`, `kid`. Provide `new`, getters, and `TryFrom<&Value>` / `From<&StatusListJwtHeader> for Value`. Application policy on `alg` (e.g. requiring `ES256`) and on `kid` (anchoring to a known DID) lives in the consumer; this struct only owns the wire shape.
* `StatusListJwtPayload` — a public struct with private fields `iss`, `sub`, `iat`, `exp`, `list`. Provide `new`, getters, `into_list`, and `TryFrom<&Value>` / `From<&StatusListJwtPayload> for Value`. The serialised form is the full payload object including the `status_list` member.
* `StatusListError` — a public enum with variants for missing/invalid fields, unsupported bit widths, base64/decompress failures, out-of-range indices, misaligned capacity (`InvalidCapacity`), and out-of-range slot values (`ValueOutOfRange`). Implements `Display` and `Error`.

## SWIYU profile constants

Top-level constants on the module, holding the values producer (issuer) and consumer (verifier) must agree on:

* `SWIYU_STATUS_LIST_TYPE = "SwissTokenStatusList-1.0"` — type tag carried in the SD-JWT VC's `status.status_list.type` field.
* `SWIYU_STATUS_LIST_BITS = 2` — slot width of the SWIYU combined revocation+suspension list.
* `SWIYU_STATUS_LIST_CAPACITY = 131_072` — slot count per list (32_768 bytes at the SWIYU `bits`).
* `STATUSLIST_JWT_TYP = "statuslist+jwt"` — JOSE `typ` value for the wallet-facing status-list JWT.

## Operations on `StatusListPointer`

* `TryFrom<&Value> for StatusListPointer` — parses a JSON object with required string `type`, integer `idx`, string `uri`. Missing or wrong-typed fields return the corresponding `StatusListError` variant.
* `From<&StatusListPointer> for Value` — emits `{ "type": <type_>, "idx": <idx>, "uri": <uri> }`. Inverse of `TryFrom<&Value>`.

## Operations on `StatusList`

* `new(bits: u8, capacity: u64) -> Result<StatusList, StatusListError>` — constructs a fresh, all-zero list. `bits` must be `1` or `2`; `capacity * bits` must be a multiple of 8 (otherwise `InvalidCapacity`).
* `from_raw(bits: u8, bytes: Vec<u8>) -> Result<StatusList, StatusListError>` — wraps an already-decompressed bitstring. Use this when the bytes have come from somewhere other than a JWT payload (e.g. the issuer's database column). `bits` must be `1` or `2`; any `bytes.len()` is accepted and yields a list whose `len()` is `bytes.len() * (8 / bits)`.
* `as_bytes() -> &[u8]` — borrowed view of the decompressed bitstring. Use when persisting the list verbatim or computing a hash over the raw layout.
* `TryFrom<&Value> for StatusList` — parses the **inner** `status_list` object (the value the JWT payload carries at the `status_list` member). Reads `bits` (default `1` per the IETF draft); rejects any `bits` other than `1` or `2` with `UnsupportedBits`. Reads `lst` as base64url-decoded compressed bytes and zlib-inflates them. The caller is responsible for extracting `status_list` from the outer payload (`payload.get("status_list")`); this matches `StatusListPointer`'s shape and keeps the API symmetric.
* `From<&StatusList> for Value` — emits the inner object: `{ "bits": <n>, "lst": <base64url> }`. Compresses with zlib (default level), base64url-encodes (`URL_SAFE_NO_PAD`). The caller wraps with `{ "status_list": <value> }` when assembling a JWT payload. Inverse of `TryFrom<&Value>`.
* `value_at(idx: u64) -> Result<StatusValue, StatusListError>`:
    * For `bits = 1`: byte at `idx / 8`, bit at `idx % 8` (LSB first).
    * For `bits = 2`: byte at `idx / 4`, two-bit window at `(idx % 4) * 2` (LSB first).
    * Out-of-range indices return `IdxOutOfRange { idx, slots }`.
* `set_at(idx: u64, value: StatusValue) -> Result<(), StatusListError>` — writes a slot. Mirror of `value_at` (same byte/bit math). Errors with `ValueOutOfRange` when the value does not fit in the list's width (e.g. `Suspended` on a 1-bit list, `Reserved(4)` on a 2-bit list); `IdxOutOfRange` for indices past the bitstring.
* `len()` returns the total number of slots: `bytes.len() * (8 / bits)`.

## Operations on `StatusListJwtHeader`

* `TryFrom<&Value>` — parses a JSON object with required string fields `alg`, `typ`, `kid`. Missing or wrong-typed fields return the corresponding `StatusListError` variant.
* `From<&StatusListJwtHeader> for Value` — emits `{ "alg", "typ", "kid" }`. Inverse of `TryFrom<&Value>`.

## Operations on `StatusListJwtPayload`

* `TryFrom<&Value>` — parses a JSON object with required string `iss`, string `sub`, integer `iat`, optional integer `exp` (absent and `null` both decode to `None`), and required object `status_list` (parsed via `StatusList::try_from`). Errors propagate from the inner `StatusList` parse unchanged.
* `From<&StatusListJwtPayload> for Value` — emits the full payload object: `{ "iss", "sub", "iat", optional "exp", "status_list": <inner object> }`. Inverse of `TryFrom<&Value>`.

## Validation rules

* `bits` must be `1` or `2`. The IETF draft also defines `4` and `8`; this crate rejects them until SWIYU has a documented use for wider widths.
* `lst` must be unpadded base64url. (`base64::URL_SAFE_NO_PAD` decoder.)
* The decompressed buffer length is not bound-checked here — applications choose their own safe ceiling at fetch time (see `swiyu-didtool`'s 1 MiB cap on the JWT itself, which transitively bounds `lst`).

# Examples

Reading a single slot from a SWIYU status-list JWT (after the application has fetched it and verified its signature):

```rust
use swiyu_core::statuslist::{StatusList, StatusValue};

let payload: serde_json::Value = /* JWT payload, after signature verification */;
let pointer_idx: u64 = /* from the SD-JWT VC's status pointer */;

let inner = payload.get("status_list").ok_or(/* … */)?;
let list = StatusList::try_from(inner)?;
match list.value_at(pointer_idx)? {
    StatusValue::Valid     => println!("credential is valid"),
    StatusValue::Revoked   => println!("credential is revoked"),
    StatusValue::Suspended => println!("credential is suspended"),
    StatusValue::Reserved(n) => println!("reserved status value {n}; treat as not valid"),
}
```

Parsing the pointer that lives inside the credential's `payload.status.status_list`:

```rust
use swiyu_core::statuslist::StatusListPointer;

let v: &serde_json::Value = /* payload.status.status_list */;
let pointer = StatusListPointer::try_from(v)?;
println!("fetch {} and read slot {}", pointer.uri(), pointer.idx());
```

Issuer-side: building a fresh list, mutating slots, and emitting the JWT payload:

```rust
use swiyu_core::statuslist::{
    StatusList, StatusListJwtPayload, StatusValue,
    SWIYU_STATUS_LIST_BITS, SWIYU_STATUS_LIST_CAPACITY,
};

let mut list = StatusList::new(SWIYU_STATUS_LIST_BITS, SWIYU_STATUS_LIST_CAPACITY)?;
list.set_at(42, StatusValue::Revoked)?;

let payload = StatusListJwtPayload::new(
    issuer_did.to_string(),
    status_registry_url.to_string(),
    iat,
    None,
    list,
);
let payload_json: serde_json::Value = (&payload).into();
// Caller signs a JWT over (header_b64 || "." || payload_json_b64).
```

Issuer-side: round-trip via the database. Read the raw bitstring, mutate, write back:

```rust
use swiyu_core::statuslist::{StatusList, StatusValue, SWIYU_STATUS_LIST_BITS};

let bytes: Vec<u8> = /* loaded from a BYTEA column */;
let mut list = StatusList::from_raw(SWIYU_STATUS_LIST_BITS, bytes)?;
list.set_at(idx, StatusValue::Suspended)?;
persist_bitstring(list.as_bytes())?;
```

# Out of scope

* Fetching the status-list JWT (HTTP/HTTPS).
* Verifying the JWT's signature against an expected issuer.
* Caching across calls.

These belong in the consuming application; see `swiyu-didtool/src/cmd/trust/verify.rs` for a concrete consumer.

# References

* [Token Status List (IETF draft)][ietf-tsl] — the underlying wire format.
* [SD-JWT VC][sd-jwt-vc] — `payload.status` claim.

[ietf-tsl]: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
[sd-jwt-vc]: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
