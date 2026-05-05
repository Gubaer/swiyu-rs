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

* `StatusListPointer` — a public struct with private fields `type_`, `idx`, `uri`. Provide `new`, `try_from_json`, and getters (`type_()`, `idx()`, `uri()`).
* `StatusList` — a public struct with private fields `bits` and `bytes`. Provide `from_payload`, `bits()`, `len()`, `is_empty()`, `value_at()`.
* `StatusValue` — a public enum with variants `Valid`, `Revoked`, `Suspended`, `Reserved(u8)`. Provide `is_valid()`.
* `StatusListError` — a public enum with variants for missing/invalid fields, unsupported bit widths, base64/decompress failures, and out-of-range indices. Implements `Display` and `Error`.

## Operations on `StatusListPointer`

* `try_from_json(v: &Value) -> Result<StatusListPointer, StatusListError>` — parses a JSON object with required string `type`, integer `idx`, string `uri`. Missing or wrong-typed fields return the corresponding `StatusListError` variant.

## Operations on `StatusList`

* `from_payload(payload: &Value) -> Result<StatusList, StatusListError>`:
    * Reads `payload.status_list.bits` (default `1` per the IETF draft).
    * Rejects any `bits` other than `1` or `2` with `UnsupportedBits`.
    * Reads `payload.status_list.lst` as base64url-decoded compressed bytes.
    * zlib-inflates the bytes; the decompressed buffer is the bitstring.
* `value_at(idx: u64) -> Result<StatusValue, StatusListError>`:
    * For `bits = 1`: byte at `idx / 8`, bit at `idx % 8` (LSB first).
    * For `bits = 2`: byte at `idx / 4`, two-bit window at `(idx % 4) * 2` (LSB first).
    * Out-of-range indices return `IdxOutOfRange { idx, slots }`.
* `len()` returns the total number of slots: `bytes.len() * (8 / bits)`.

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

let list = StatusList::from_payload(&payload)?;
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
let pointer = StatusListPointer::try_from_json(v)?;
println!("fetch {} and read slot {}", pointer.uri(), pointer.idx());
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
