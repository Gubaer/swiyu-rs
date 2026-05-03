# Aspect: Key Management

## What we manage

For every issuer `I`, swiyu-issuer manages three private keys, one per role:

- **`assert`** — used to sign Verifiable Credentials issued by `I`. ECDSA over P-256 key pair.
- **`authorized`** — used to sign the `DataIntegrityStatement` in entries of `I`'s DIDLog. EdDSA (Ed25519) key pair.
- **`authentication`** — not used by swiyu-issuer for any signing operation. We still have to generate the key pair so its public key can be embedded in `I`'s DIDLog entries. ECDSA over P-256 key pair.

Together these three key pairs form a **key triple** for `I`. These algorithm and curve choices (Ed25519, P-256) are dictated by SWIYU.

## What we do not manage

- **Public keys.** We do not persist the public keys locally. They are part of `I`'s DIDLog, which is stored in the SWIYU Identity Registry, and can always be read from there.
- **Older key generations.** Over the lifecycle of `I` and its DID there are multiple generations of key triples. swiyu-issuer only signs with the latest (currently active) triple. Older private keys are never used for signing again. Verifiers that need older public keys read them from `I`'s DIDLog.

## SigningEngine

All private-key operations are performed by a **SigningEngine**. The fundamental rule is:

> A private key never leaves the SigningEngine. Signing always happens in the SigningEngine's process space — never in the process space of `issuer-mgt` or `issuer-odbc`.

### Capabilities

The SigningEngine exposes three operations:

- `generate_keypair(role) -> (id, public_key)`
  - Generates a key pair appropriate to the role:
    - `authorized` → EdDSA (Ed25519)
    - `assert`, `authentication` → ECDSA
  - Persists the private key inside the engine.
  - Returns the public key and an opaque key pair identifier.

- `sign(id, input) -> signature`
  - `input` is a 32-byte array.
  - For ECDSA key pairs, the input is treated as a digest (typical ECDSA-over-hash usage).
  - For EdDSA key pairs, the input is treated as the **message** to sign with plain Ed25519 — *not* Ed25519ph. The engine feeds exactly those 32 bytes into Ed25519 as the message.
  - Returns an ECDSA or EdDSA signature accordingly. ECDSA signatures are returned as raw `r || s` (each integer padded to the curve's field size). Ed25519 signatures are returned in the standard 64-byte form. If a backend produces a different encoding (e.g. DER), the engine normalizes before returning.

- `delete_keypair(id)`
  - Optional. swiyu-issuer may also choose to leave obsolete key pairs in place inside the engine.

The SigningEngine has **no** `rotate` operation. Rotation is a choreography owned by swiyu-issuer (see below).

### Key pair identifiers

Identifiers are **opaque** to swiyu-issuer. Their concrete form depends on the SigningEngine implementation (HSM handle, software-vault key reference, database row id, etc.). swiyu-issuer treats them as values to store and pass back.

### Maturity levels

A SigningEngine implementation can sit at one of three maturity levels:

- **High** — backed by a Hardware Security Module (HSM).
- **Middle** — backed by a software vault such as HashiCorp Vault.
- **Low** — backed by storage on disk or in a database, with private keys persisted unencrypted.

### Requirements

- **Production:** the deployed SigningEngine must be of high maturity (HSM-backed).
- **Development:** for convenience, swiyu-issuer ships with a low-maturity SigningEngine.
- **Middle:** open — we have not yet decided whether we will implement a Vault-backed SigningEngine.
- **HSM algorithm support:** an HSM-backed SigningEngine must support both Ed25519 (`CKM_EDDSA`, plain mode) and ECDSA over P-256 (`CKM_ECDSA` with curve `secp256r1`). These are non-negotiable because SWIYU requires them.

## Rotation choreography

Because the SigningEngine has no `rotate` operation, and because key pair identifiers are per-key-pair (not per-role-slot), key rotation is performed by swiyu-issuer as follows:

1. **Generate the new triple.** For each role, call `engine.generate_keypair(role)` to obtain a new `(id, public_key)`. swiyu-issuer now holds three new identifiers and three new public keys, but they are not yet active.
2. **Build the new DIDLog entry.** Embed the three new public keys in the appropriate positions of the entry.
3. **Sign with the old `authorized` key.** Call `engine.sign(old_authorized_id, hash_of_entry)`. The old private key never leaves the engine; signing happens in the engine's process space.
4. **Submit to the registry.** Push the signed entry to the SWIYU Identity Registry.
5. **Atomically swap the active triple.** On successful registry write, swiyu-issuer atomically updates its mapping `(issuer, role) → current_id` from the three old identifiers to the three new ones.
6. **Optionally delete the old key pairs.** swiyu-issuer may call `engine.delete_keypair(old_id)` for the three obsolete identifiers, or leave them in the engine.

### Properties of this design

- Private keys never leave the SigningEngine at any step.
- "Which identifier is current for `(issuer, role)`" is swiyu-issuer's state — not the engine's.
- At the SigningEngine layer there is no concept of rotation overlap; multiple key pairs for the same role exist independently as separate identifiers.
- At the swiyu-issuer layer, the overlap window is bounded by the duration of one DIDLog write to the registry.
