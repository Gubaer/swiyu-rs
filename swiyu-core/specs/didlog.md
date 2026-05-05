This is the specification for the `didlog` module in this repository.

The `didlog` module provides data structures for a DID Log and its entries. It supports two
versions of the DID method specification, both of which are in active use:

- [did:tdw v0.3][did-tdw-v0-3] — used in the current Beta Swiss Trust Infrastructure
- [did:webvh v1.0][did-webvh-v1-0] — targeted for the future production Trust Infrastructure

[did-tdw-v0-3]: https://identity.foundation/didwebvh/v0.3/
[did-webvh-v1-0]: https://identity.foundation/didwebvh/v1.0/

---

# Log entry format

The two versions use different wire formats for log entries.

**v0.3** — five-element JSON array:
```json
[ versionId, versionTime, parameters, DIDDocState, DataIntegrityProof ]
```

**v1.0** — named-field JSON object:
```json
{
  "versionId":   "1-<hash>",
  "versionTime": "2024-...",
  "parameters":  { },
  "state":       { },
  "proof":       [ ]
}
```

The fields carry the same semantic content in both versions. `DIDDocState` was renamed to
`state` and `DataIntegrityProof` to `proof` in v1.0.

---

# `LogEntryFormat`

```rust
pub enum LogEntryFormat {
    TDW03,
    WebVH10,
}
```

Indicates which wire format a `DIDLogEntry` was parsed from, and controls which wire format
the `From<DIDLogEntry> for Value` impl emits. It has no influence on any other logic.

---

# `DIDLogEntry`

A single entry in the DID log. Internally the representation is identical for both versions;
`LogEntryFormat` records only the wire format.

```rust
pub struct DIDLogEntry {
    format:               LogEntryFormat,
    version_id:           String,
    version_time:         String,
    parameters:           LogParameters,
    did_doc_state:        DIDDocState,
    data_integrity_proofs: Vec<Value>,
}
```

## Constructors

```rust
DIDLogEntry::new_tdw(
    version_id: String,
    version_time: String,
    parameters: LogParameters,
    did_doc_state: DIDDocState,
    data_integrity_proofs: Vec<Value>,
) -> Self
```

Creates a v0.3 entry (`format = LogEntryFormat::TDW03`).

```rust
DIDLogEntry::new_webvh(
    version_id: String,
    version_time: String,
    parameters: LogParameters,
    did_doc_state: DIDDocState,
    data_integrity_proofs: Vec<Value>,
) -> Self
```

Creates a v1.0 entry (`format = LogEntryFormat::WebVH10`).

## Parsing

```rust
impl TryFrom<&Value> for DIDLogEntry {
    type Error = DIDLogError;
}
```

Auto-detects the wire format:
- If `v` is a JSON array → parse as v0.3, set `format = LogEntryFormat::TDW03`
- If `v` is a JSON object → parse as v1.0, set `format = LogEntryFormat::WebVH10`
- Otherwise → `Err(DIDLogError::InvalidFormat(...))`

## Serialisation

```rust
impl From<DIDLogEntry> for Value
```

Emits the wire format recorded in the entry's `format`:
- `TDW03` → five-element JSON array using field names `DIDDocState` / `DataIntegrityProof`
- `WebVH10` → named-field JSON object using field names `state` / `proof`

## Getters

```rust
fn format(&self)                 -> &LogEntryFormat
fn version_id(&self)             -> &str
fn version_time(&self)           -> &str
fn parameters(&self)             -> &LogParameters
fn did_doc_state(&self)          -> &DIDDocState
fn data_integrity_proofs(&self)  -> &[Value]
```

---

# `DIDLog`

The full DID log: a sequential list of entries stored as JSON Lines (`did.jsonl`).

```rust
pub struct DIDLog {
    entries: Vec<DIDLogEntry>,
}
```

## Constructor

```rust
DIDLog::new(entries: Vec<DIDLogEntry>) -> Self
```

## Getter

```rust
fn entries(&self) -> &[DIDLogEntry]
```

---

# `LogParameters`

The `parameters` field of a log entry. All fields are optional; only those present in a given
entry are serialised.

```rust
pub struct LogParameters {
    method:          Option<String>,
    scid:            Option<String>,
    update_keys:     Option<Vec<String>>,
    prerotation:     Option<bool>,
    next_key_hashes: Option<Vec<String>>,
    portable:        Option<bool>,
    deactivated:     Option<bool>,
    ttl:             Option<u64>,
    witness:         Option<Value>,
    watchers:        Option<Vec<String>>,   // v1.0 only
}
```

`watchers` is parsed and serialised only when the enclosing entry uses `LogEntryFormat::WebVH10`.

Getters are provided for all fields.

---

# `DIDDocState`

The DID document state carried by a log entry — either a full replacement or an incremental
JSON Patch.

```rust
pub enum DIDDocState {
    Value(Value),
    Patch(Value),
}
```

---

# `DIDLogError`

```rust
pub enum DIDLogError {
    InvalidFormat(String),
    MissingField(String),
    InvalidFieldType(String),
}
```

---

# Support for SCIDs

Add a module `didlog::scid`.

Provide a struct for a SCID with an `impl` block:
- No constructors
- `try_from_string` method and matching `TryFrom` implementation
- `to_string` method
- Getters for the hash algorithm, hash length, and raw hash value

---

# Lessons Learned

Notes captured while making `didtool create --swiyu --format tdw` round-trip
through the SWIYU integration registry. They focus on details that are easy to
get wrong from a casual read of the did:tdw 0.3 spec.

## Shape of a genesis log entry

A did:tdw 0.3 genesis log entry is a 5-element JSON array:

```
[ versionId, versionTime, parameters, state, proof ]
```

- `versionId` — the string `"1-<entryHash>"` (see below; `<entryHash>` is *not*
  the SCID).
- `versionTime` — ISO-8601 UTC, **strictly in the past**. The registry rejects
  entries whose `versionTime` is not strictly less than its own clock; backdate
  by a few seconds to absorb skew.
- `parameters` — object with `method`, `scid`, `updateKeys`, `portable`, …
- `state` — `{"value": <DID document>}` for did:tdw. (did:webvh 1.0 stores the
  DID document directly under `state`, without the `value` envelope — different
  method, different shape.)
- `proof` — array of one DataIntegrityProof.

## Two distinct hashes: SCID and entryHash

The genesis entry uses **two different** base58btc-multihash-SHA256 values,
both computed over the **proof-less, 4-element** form of the entry (the proof
slot is excluded entirely — *not* an empty array `[]`):

1. **SCID** — hash of the *preliminary* entry, where:
   - `versionId` is the literal placeholder `"{SCID}"` (not `"1-{SCID}"`),
   - every SCID-bearing position (`parameters.scid`, the DID `id`, controllers,
     verification-method `id`s, …) is `"{SCID}"`,
   - the proof slot is omitted (4 elements).

2. **entryHash** — hash of the same 4-element entry after substituting the
   actual SCID everywhere, *except* `versionId`, which becomes the **bare SCID
   with no `"1-"` prefix**. The spec rule: "set versionId to the previous
   entry's versionId; for the genesis entry, set it to the SCID."

Both hashes are computed as
`base58btc(multihash(SHA-256(JCS(entry)), 0x12))`,
using JCS canonicalisation (RFC 8785).

## versionId

After entryHash is known, set the on-disk
`versionId = "1-" + entryHash`. The proof's `challenge` is this final value.

## Data Integrity Proof

- `cryptosuite: "eddsa-jcs-2022"`, signed by the authorized Ed25519 key.
- `verificationMethod` references the key as `did:key:<multikey>#<multikey>`.
- `proofPurpose: "authentication"` for did:tdw (the DID Toolbox / SWIYU
  convention; did:webvh 1.0 uses `"assertionMethod"`).
- `challenge` is the final `versionId` (`"1-<entryHash>"`).
- Signed bytes are `SHA256(JCS(proofConfig)) ‖ SHA256(JCS(documentToSign))`.
  **DID Toolbox quirk:** `documentToSign` is only the inner DID document —
  `entry[3]["value"]` for did:tdw — not the whole log entry. The Rust port
  mirrors this to match Toolbox-produced signatures.
- `proofValue` is `"z" + base58btc(signature)`.

## SWIYU registry interaction

- `POST /api/v1/identifier/business-entities/<partner>/identifier-entries`
  allocates the DID space and returns an `identifierRegistryUrl`. The trailing
  UUID becomes part of the DID's path component.
- `PUT /api/v1/identifier/business-entities/<partner>/identifier-entries/<uuid>`
  uploads the JSONL line. Content-Type: `application/jsonl+json`. Bearer auth
  with `SWIYU_ACCESS_TOKEN`.

## Pitfalls that cost real time

- **Treating SCID and entryHash as the same value.** They aren't, even for the
  genesis entry. SCID has placeholder positions; entryHash has the real SCID
  everywhere except `versionId` (where it's the bare SCID).
- **Including an empty `[]` proof slot when hashing.** The proof slot must be
  omitted from the array entirely (4 elements), not present-but-empty.
- **Putting `"1-{SCID}"` in the preliminary `versionId`.** It must be just
  `"{SCID}"`.
- **Relying on `serde_json::to_string` as a JCS substitute.** With the default
  `BTreeMap`-backed `serde_json::Map` and ASCII-only content the bytes usually
  match JCS — but only by coincidence. Always use `serde_jcs::to_vec` for
  hashing inputs.
- **Using `state.value` shape for did:webvh.** That envelope is did:tdw-only;
  did:webvh 1.0 places the DID document directly under `state` and rejects
  entries that wrap it in `value`.

## Implementation in this crate

- `swiyu_core::didlog::scid::derive_scid(&Value) -> String` — preliminary-entry
  hasher (input contract documented on the function).
- `swiyu_core::didlog::scid::derive_entry_hash(&Value) -> String` — same
  algorithm, different input contract (SCID substituted; `versionId` is the
  previous entry's `versionId` or the bare SCID for genesis).
- Both are pinned to a known-good SWIYU vector by unit tests in `scid.rs`.
