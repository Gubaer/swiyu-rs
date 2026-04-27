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
`to_json` emits. It has no influence on any other logic.

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
DIDLogEntry::try_from_json(v: &Value) -> Result<Self, DIDLogError>
```

Auto-detects the wire format:
- If `v` is a JSON array → parse as v0.3, set `format = LogEntryFormat::TDW03`
- If `v` is a JSON object → parse as v1.0, set `format = LogEntryFormat::WebVH10`
- Otherwise → `Err(DIDLogError::InvalidFormat(...))`

## Serialisation

```rust
DIDLogEntry::to_json(&self) -> Value
```

Emits the wire format recorded in `self.format`:
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
