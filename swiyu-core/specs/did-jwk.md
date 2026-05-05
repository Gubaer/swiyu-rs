This is the specification for the `didjwk` module in this repository.

The `didjwk` module provides the data structures and operations for a DID according to the [did:jwk][did-jwk-spec] specification.

# Motivation

`did:jwk` is a self-contained DID method: the entire public key is encoded directly in the identifier, so no registry lookup is required to resolve it. In the Swiss Trust Infrastructure context, `did:jwk` is the natural choice for identifying *credential holders* (wallet keys), because:

* Holder keys are typically ephemeral, often generated per credential.
* Registering each holder key in the Identifier Registry would be both expensive and inappropriate.
* The OID4VCI proof-of-possession JWT can carry `kid: did:jwk:...` to reference the holder key without any out-of-band resolution.

`did:tdw` and `did:webvh` remain the methods used for *issuer* and *verifier* DIDs (which need verifiable history and registry presence). The two roles use different DID methods, and the `swiyu-core` crate must support both.

# Scope

In scope:

* Parsing a `did:jwk` identifier into the embedded JWK.
* Constructing a `did:jwk` identifier from a JWK.
* Synthesising a DID Document for a `did:jwk` identifier (per the spec, the document is fully derivable from the identifier itself — no I/O needed).
* Validation of the embedded JWK shape.
* Support for the curves used by the SWIYU ecosystem and OID4VCI wallets.

Out of scope (deferred):

* `did:key` (related but distinct DID method; covered by a future spec if needed).
* Asymmetric algorithms beyond those listed under [Supported algorithms](#supported-algorithms).
* Private-key handling. `did:jwk` is by definition a *public* key encoding; private key storage stays in the `keystore` of `swiyu-didtool`.
* Key generation. Keypair generation is the keystore's concern; this module only consumes existing public keys.

# Format recap

```
did:jwk:<base64url(json)>
```

where `<json>` is the UTF-8 JSON serialisation of a public JWK (RFC 7517) without whitespace. The base64url encoding is unpadded (RFC 4648 §5).

The DID Document is synthesised on the fly:

* `id`: the `did:jwk:...` identifier itself
* one verification method with id `<did>#0`, type `JsonWebKey2020`, controller `<did>`, and `publicKeyJwk` set to the decoded JWK
* `authentication`, `assertionMethod`, `keyAgreement` (when applicable), `capabilityInvocation`, `capabilityDelegation` all referencing `<did>#0`

# Requirements

## Module placement

* The module must live in `swiyu-core` as `didjwk` (file: `src/didjwk/mod.rs`).
* The module must be re-exported from `lib.rs` so it is reachable as `swiyu_core::didjwk`.

## Public types

* The module must provide a public struct `DIDJwk` representing a parsed `did:jwk` identifier.
* `DIDJwk` must hold:
    * the original DID string (for round-tripping without re-encoding)
    * the decoded `PublicKeyJWK` (reusing the existing `diddoc::PublicKeyJWK` type)
* Provide a public error enum `DIDJwkError` covering at least:
    * `MissingPrefix` — input does not start with `did:jwk:`
    * `InvalidBase64` — the suffix is not valid unpadded base64url
    * `InvalidJson` — the decoded bytes are not valid JSON
    * `InvalidJwk(reason)` — the JSON is not a structurally valid JWK
    * `UnsupportedAlgorithm(kty_or_crv)` — the JWK uses an algorithm outside [Supported algorithms](#supported-algorithms)
    * `PrivateKeyMaterial` — the JWK contains private key components (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`); these must be rejected for `did:jwk`

## Operations on `DIDJwk`

* `DIDJwk::parse(input: &str) -> Result<DIDJwk, DIDJwkError>` — parses a `did:jwk:...` string.
* `DIDJwk::from_jwk(jwk: &PublicKeyJWK) -> Result<DIDJwk, DIDJwkError>` — encodes a JWK into a `did:jwk` identifier.
* `DIDJwk::as_str(&self) -> &str` — returns the original (or canonically reconstructed) `did:jwk:...` string.
* `DIDJwk::jwk(&self) -> &PublicKeyJWK` — returns a reference to the decoded JWK.
* `DIDJwk::to_diddoc(&self) -> DIDDoc` — synthesises the DID Document.
* Implement `FromStr` and `Display` mirroring `parse` / `as_str` to be consistent with the existing `DID` type.

## Encoding rules

* When constructing a `did:jwk` from a `PublicKeyJWK`:
    * The JWK must be serialised to JSON in canonical form (RFC 8785 / JCS) before base64url encoding. The crate already depends on `serde_jcs`; reuse it.
    * Any private key components present in the input must cause `from_jwk` to return `PrivateKeyMaterial` rather than silently stripping them. (Stripping silently would risk surprising callers about key provenance.)
* When parsing:
    * Accept only unpadded base64url. Reject padded variants explicitly.
    * Do not require the JSON to be canonical on input — only the round-tripped form (via `from_jwk`) is canonical. The original string is preserved by `as_str` so signatures over the DID string remain verifiable.

## Validation rules

A JWK decoded from a `did:jwk` is valid when:

* `kty` is present and is one of: `OKP`, `EC`. (`RSA`, `oct` are out of scope for now.)
* For `kty = OKP`: `crv` is `Ed25519`, and `x` is base64url-encoded.
* For `kty = EC`: `crv` is `P-256`, and both `x` and `y` are base64url-encoded.
* No private key components (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) are present.
* `use` and `key_ops`, if present, are not contradictory (best-effort sanity check; do not over-validate).

## DID Document synthesis

* `to_diddoc` must produce a `DIDDoc` whose:
    * `id` equals the `did:jwk:...` string
    * `verification_method` contains exactly one entry with id `<did>#0`, type `JsonWebKey2020`, controller `<did>`, and the JWK as `publicKeyJwk`
    * `authentication`, `assertion_method`, `capability_invocation`, `capability_delegation` are all `[<did>#0]`
    * `key_agreement` is `[<did>#0]` only when the key type supports key agreement (currently: never for `Ed25519` or `P-256` signing keys; reserved for future X25519/P-256 ECDH variants)

# Supported algorithms

| `kty` | `crv`     | JOSE alg | Status        | Use case                            |
|-------|-----------|----------|---------------|--------------------------------------|
| OKP   | Ed25519   | EdDSA    | **required**  | Aligns with SWIYU issuer signing keys; common in test holders. |
| EC    | P-256     | ES256    | **required**  | Most common holder key in OID4VCI wallets. |
| EC    | secp256k1 | ES256K   | future        | Add when a real wallet requires it.  |
| RSA   | —         | RS256    | not supported | Out of scope for the SWIYU ecosystem. |
| oct   | —         | —        | not supported | Symmetric keys are not valid for `did:jwk`. |

# Examples

Ed25519 example (lifted from the [did:jwk spec][did-jwk-spec]):

```
did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9
```

Decoded JWK:

```json
{"crv":"P-256","kty":"EC","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}
```

Synthesised DID Document (abridged):

```json
{
  "id": "did:jwk:eyJjcnYi...",
  "verificationMethod": [{
    "id": "did:jwk:eyJjcnYi...#0",
    "type": "JsonWebKey2020",
    "controller": "did:jwk:eyJjcnYi...",
    "publicKeyJwk": { "crv": "P-256", "kty": "EC", "x": "...", "y": "..." }
  }],
  "authentication": ["did:jwk:eyJjcnYi...#0"],
  "assertionMethod": ["did:jwk:eyJjcnYi...#0"],
  "capabilityInvocation": ["did:jwk:eyJjcnYi...#0"],
  "capabilityDelegation": ["did:jwk:eyJjcnYi...#0"]
}
```

# Testing

* Unit tests in `src/didjwk/mod.rs` under `#[cfg(test)]`:
    * Parse the spec example above and check the decoded JWK.
    * Round-trip `from_jwk` → `parse` and confirm the JWK matches.
    * Reject inputs missing the `did:jwk:` prefix.
    * Reject inputs with padded base64url.
    * Reject JWKs containing private key material.
    * Reject `kty: RSA` and `kty: oct` with `UnsupportedAlgorithm`.
    * Synthesise a DID Document and confirm the verification method is `<did>#0` with the expected JWK.
* No integration tests required at this stage; `did:jwk` has no I/O.

# Open questions

* Should `DIDJwk` integrate into a unified `enum AnyDID { Tdw(DID), WebVh(DID), Jwk(DIDJwk) }` so callers can accept any DID method generically? Defer until a concrete caller (e.g., `swiyu-issuer` verifying holder proof JWTs) needs it.
* Whether to canonicalise on parse as well as on encode. Current decision: preserve original string on parse, canonicalise on construction. Revisit if signature verification over the DID string proves problematic.
* Whether to accept legacy padded base64url. Current decision: reject. The spec mandates unpadded; being strict catches buggy producers.

# References

* [did:jwk Method Specification][did-jwk-spec] (W3C CCG)
* [RFC 7517 — JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
* [RFC 7518 — JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518)
* [RFC 8785 — JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
* [RFC 4648 §5 — Base64url encoding](https://www.rfc-editor.org/rfc/rfc4648#section-5)

[did-jwk-spec]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
