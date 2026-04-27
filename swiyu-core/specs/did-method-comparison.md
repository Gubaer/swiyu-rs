# did:tdw v0.3 vs did:webvh v1.0 — Comparison

## How this document was produced

This comparison was produced by Claude (claude-sonnet-4-6) by fetching and analysing the two published specification documents:

- [did:tdw v0.3](https://identity.foundation/didwebvh/v0.3/) — used in the current Beta Swiss Trust Infrastructure
- [did:webvh v1.0](https://identity.foundation/didwebvh/v1.0/) — targeted for the future production Trust Infrastructure, supported by DID-Toolbox since version 1.6

The intermediate versions v0.4 and v0.5 were also fetched to attribute each change to the version in which it was introduced. No human review of the raw specs was performed; the summary reflects what the published HTML documents contain.

---

## Background

`did:tdw` and `did:webvh` are the same DID method under two names. The method was renamed from *Trust DID Web* (`did:tdw`) to *Web + Verifiable History* (`did:webvh`) in v0.5. Both extend `did:web` by adding a cryptographically chained, append-only log that makes the full history of a DID document verifiable without a ledger.

The changes from v0.3 to v1.0 span three intermediate releases. The most impactful are a breaking change to the log entry format (v0.4) and a simplification of the witness model (v1.0).

---

## Major Differences

### 1. Method Rename (introduced in v0.5)

The method identifier changed from `did:tdw` to `did:webvh`. All DIDs and the `method` parameter value reflect this:

| | v0.3 | v1.0 |
|---|---|---|
| DID prefix | `did:tdw:` | `did:webvh:` |
| `method` parameter | `"did:tdw:0.3"` | `"did:webvh:1.0"` |

---

### 2. Log Entry Format: Array → Object (introduced in v0.4)

The most significant breaking change. Each log entry changed from a positional JSON array to a named-field JSON object.

**v0.3** — five-element array:
```json
[ versionId, versionTime, parameters, DIDDocState, DataIntegrityProof ]
```

**v1.0** — named fields:
```json
{
  "versionId": "1-<hash>",
  "versionTime": "2024-...",
  "parameters": { },
  "state": { },
  "proof": [ ]
}
```

Two fields were also renamed: `DIDDocState` → `state`, `DataIntegrityProof` → `proof`.

---

### 3. Witness Model Simplified (introduced in v1.0)

The weighted approval model was replaced with a simpler count-based model.

**v0.3 / v0.4 / v0.5** — weighted witnesses:
```json
"witness": {
  "threshold": 4,
  "selfWeight": 2,
  "witnesses": [
    { "id": "<DID>", "weight": 1 },
    { "id": "<DID>", "weight": 1 }
  ]
}
```
Threshold = sum of accumulated weights (including `selfWeight`).

**v1.0** — count-based witnesses:
```json
"witness": {
  "threshold": 2,
  "witnesses": [
    { "id": "did:key:..." },
    { "id": "did:key:..." }
  ]
}
```
Threshold = minimum number of witness proofs required. `selfWeight` and per-witness `weight` are removed. Witnesses must be `did:key` DIDs.

---

### 4. Separate Witness File (introduced in v0.5)

Witness proofs are no longer embedded directly in the log entry at publication time. They are published in a separate `did-witness.json` file **before** the log entry is appended to `did.jsonl`. Resolvers fetch this file independently.

---

### 5. Pre-Rotation Key Semantics Changed (introduced in v1.0)

**v0.3**: Active `updateKeys` are always taken from the prior entry — key rotation takes effect only after publication.

**v1.0**:
- Without pre-rotation active: use keys from the previous entry (same as v0.3).
- With pre-rotation active: use keys from the **current** entry — rotation takes effect immediately. The `nextKeyHashes` commitment in the prior entry serves as proof of authorization for the new keys.

---

### 6. New: `watchers` Parameter (introduced in v1.0)

A new optional `watchers` parameter holds an array of URLs pointing to monitoring services. Watchers independently cache and observe the DID log, providing redundant resolution and detection of malicious controller behaviour.

```json
"watchers": ["https://watcher.example.com/"]
```

---

### 7. Two Deactivation Modes (introduced in v1.0)

**v0.3**: Only one approach — set `"deactivated": true` in parameters.

**v1.0** adds an alternative: set `updateKeys` to an empty array without the `deactivated` flag. The DIDDoc remains resolvable but no further updates are possible. The DID-CORE-compliant mode (`deactivated: true`) causes resolvers to withhold the DIDDoc entirely.

---

### 8. Proof Purpose Made Explicit (introduced in v1.0)

Data Integrity proofs must now declare `"proofPurpose": "assertionMethod"` explicitly.

---

### 9. Resolution Metadata and Error Format Formalised (introduced in v1.0)

v1.0 mandates a structured resolution metadata object including `versionId`, `versionTime`, `created`, `updated`, `scid`, `portable`, `deactivated`, `ttl`, `witness`, and `watchers`.

Error responses must follow **RFC 9457 Problem Details** format (`type`, `title`, `detail`).

---

### 10. Default `ttl` Defined (introduced in v1.0)

The `ttl` parameter now has an explicit default of **3600 seconds** when absent, rather than being undefined.

---

## Summary Table

| Aspect | v0.3 (did:tdw) | v1.0 (did:webvh) |
|---|---|---|
| Method name | `did:tdw` | `did:webvh` |
| Log entry format | JSON array | JSON object |
| DIDDoc state field | `DIDDocState` | `state` |
| Proof field | `DataIntegrityProof` | `proof` |
| Witness threshold | Weighted sum | Simple count |
| `selfWeight` | Present | Removed |
| Per-witness `weight` | Present | Removed |
| Witness proofs location | Inline in log entry | Separate `did-witness.json` |
| Pre-rotation key window | Always prior entry | Current entry (when pre-rotation active) |
| Watchers | Not supported | `watchers` parameter |
| Deactivation options | `deactivated: true` only | + empty `updateKeys` alternative |
| `ttl` default | Undefined | 3600 s |
| Error response format | Unspecified | RFC 9457 Problem Details |
| Proof purpose | Implicit | Explicit `assertionMethod` |
