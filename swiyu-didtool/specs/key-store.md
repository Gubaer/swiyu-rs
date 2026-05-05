The `KeyStore` persists key pairs for generated DIDs on disk.

# Directory layout

```
<root>/
  <name>/
    0001/                          ← sequence number from versionId (4-digit, zero-padded)
      authorized-private.pem       ← EdDSA (signs DID log entries)
      authorized-public.pem
      authentication-private.pem   ← ECDSA (DID authentication)
      authentication-public.pem
      assertion-private.pem        ← ECDSA (signs verifiable credentials)
      assertion-public.pem
    0002/                          ← full snapshot of all three active key pairs after an update
      authorized-private.pem
      authorized-public.pem
      authentication-private.pem
      authentication-public.pem
      assertion-private.pem
      assertion-public.pem
    did.txt                        ← the full DID string
```

Each numbered subdirectory is a **full snapshot** of all three active key pairs at that version
— not a delta. This keeps `lookup` simple: the highest-numbered subdirectory always contains
the complete current key set, with no need to walk backwards through history to reconstruct it.

Old snapshots are retained so that signatures on past DID log entries and verifiable credentials
can still be verified against the keys that were active at the time.

The subdirectory number matches the sequence number that prefixes the `versionId` of the
corresponding DID log entry (e.g. `versionId` `2-QmHash…` → subdirectory `0002`). The
4-digit zero-padding ensures lexicographic and numeric order agree; it accommodates up to
9 999 updates per DID, which is sufficient for any realistic key-rotation cadence.

The default root directory is `~/.didtool/keys` (the user's home directory,
resolved at runtime).

Each entry's subdirectory name is derived automatically as the first 12 hex
characters of the BLAKE3 hash of the DID string (48 bits, sufficient
collision resistance for the number of DIDs a single user manages). Example:
`did:webvh:abc123:example.com` → `3f7a2c91b04e`

BLAKE3 is chosen over SHA-256 for its speed and suitability for
non-cryptographic content addressing. The `blake3` crate is used.

The `did.txt` file serves two purposes:
* **Verification** — `lookup` reads `did.txt` and confirms it matches the
  requested DID before returning the entry, guarding against the theoretical
  hash collision.
* **Human legibility** — a user browsing the directory can open `did.txt` to
  identify which DID an opaque subdirectory belongs to.

# Opening a `KeyStore`

```rust
KeyStore::open(path: &Path) -> Result<KeyStore, KeyStoreError>
```

Opens an existing `KeyStore` rooted at `path`. Fails if the directory does
not exist.

```rust
KeyStore::open_or_create(path: &Path) -> Result<KeyStore, KeyStoreError>
```

Opens the `KeyStore` at `path`, creating the root directory if it does not
already exist.

```rust
KeyStore::default() -> Result<KeyStore, KeyStoreError>
```

Equivalent to `open_or_create("~/.didtool/keys")`.

# Key pairs

Each snapshot subdirectory holds exactly three key pairs — one per role:

| Role           | Algorithm | Purpose                          |
|----------------|-----------|----------------------------------|
| authorized     | EdDSA     | Signs DID log entries            |
| authentication | ECDSA     | DID authentication               |
| assertion      | ECDSA     | Signs verifiable credentials     |

See [authorized keys][authorized-keys], [authentication][authentication],
and [assertion][assertion] for the respective specifications.

[authorized-keys]: https://identity.foundation/didwebvh/v1.0/#authorized-keys
[authentication]: https://www.w3.org/TR/did-1.0/#authentication
[assertion]: https://www.w3.org/TR/did-1.0/#assertion

# Operations

Creating a new key store entry is a two-phase operation, because the full DID (including
the SCID) is not known until after the public keys have been generated and incorporated into
the genesis DID document:

1. **`generate`** — generates the three key pairs and returns them in memory as `StagedKeys`.
   The caller uses the public keys to build the initial DID document, derives the SCID, and
   constructs the full DID.
2. **`commit`** — called once the full DID is known. Writes the keys to disk under the correct
   subdirectory and records `did.txt`.

```rust
KeyStore::generate() -> Result<StagedKeys, KeyStoreError>
```

Generates all three key pairs and returns them in memory. No filesystem I/O is performed.
The caller extracts the public keys from `StagedKeys` to build the DID document.

```rust
struct StagedKeys { /* opaque */ }

impl StagedKeys {
    fn authorized_verifying_key(&self)     -> &Ed25519VerifyingKey
    fn authentication_verifying_key(&self) -> &EcdsaVerifyingKey
    fn assertion_verifying_key(&self)      -> &EcdsaVerifyingKey
}
```

```rust
KeyStore::commit(&self, staged: StagedKeys, did: &Did) -> Result<KeyStoreEntry, KeyStoreError>
```

Writes the staged key pairs into a `0001/` snapshot subdirectory for `did` and writes
`did.txt`. Fails with `KeyStoreError::AlreadyExists` if an entry for this DID already
exists.

```rust
KeyStore::lookup(&self, did: &Did) -> Result<Option<KeyStoreEntry>, KeyStoreError>
```

Computes the subdirectory name from `did`, checks whether it exists, reads
`did.txt` and verifies it matches `did`, then loads the key pairs from the
highest-numbered snapshot subdirectory and returns the entry. Returns
`Ok(None)` if no subdirectory exists. Returns `Err(KeyStoreError::Mismatch)`
if the subdirectory exists but `did.txt` contains a different DID (hash
collision or corruption).

```rust
KeyStore::remove(&self, did: &Did) -> Result<(), KeyStoreError>
```

Removes the subdirectory for `did` and all its contents. Fails if no entry
for this DID exists.

```rust
KeyStore::exists(&self, did: &Did) -> bool
```

Returns `true` if a subdirectory for `did` exists.

```rust
KeyStore::list(&self) -> Result<Vec<KeyStoreListEntry>, KeyStoreError>
```

Returns one entry per DID in the key store, sorted by hash. Each entry exposes the
12-character BLAKE3 hash and the full DID string read from `did.txt`.

```rust
struct KeyStoreListEntry {
    hash: String,   // 12-character BLAKE3 hex prefix (the subdirectory name)
    did:  String,   // full DID string from did.txt
}
```

This is the primary way users discover the short hash handle for a DID, which they
can then pass to other commands instead of typing the full DID string. The intended
workflow is:

```
$ didtool key list
3f7a2c91b04e  did:webvh:abc123:example.com
9b1d4e72f3a1  did:webvh:def456:other.example.com

$ didtool key show --did 3f7a2c91b04e
```

The two-column output (hash, DID separated by two spaces) is designed to be
`grep`- and `awk`-friendly.

# CLI API

The `didtool key` subcommand exposes read-only access to the key store. Keys and key
pairs are never inserted directly through the CLI — they are created as a side effect of
DID operations such as `didtool did create` and `didtool did rotate`.

## `didtool key list`

Lists all entries in the key store, one per line, sorted by hash:

```
3f7a2c91b04e  did:webvh:abc123:example.com
9b1d4e72f3a1  did:webvh:def456:other.example.com
```

Two-column output (hash, DID separated by two spaces) for easy `grep`/`awk` use.

## `didtool key show <hash|did> [--role authorized|authentication|assertion] [--version <n>]`

Displays public key(s) to stdout. Private keys are never shown on stdout — use `export`
for those.

- Without `--role`: displays all three public keys for the entry.
- With `--role`: displays only the public key for that role.
- `--version` selects a specific snapshot; defaults to the latest.
- `<hash|did>`: accepts either the 12-character BLAKE3 hash or the full DID string.

## `didtool key export <hash|did> --role authorized|authentication|assertion --out <file> [--private] [--version <n>]`

Writes a single key to `--out` in PEM format. PEM is the only supported format,
consistent with the crypto module.

- `--role` is required — one key is exported at a time.
- Without `--private`: exports the public key.
- `--private`: exports the private key. Requires an explicit flag to make the intent
  clear and auditable in shell history.
- `--version` selects a specific snapshot; defaults to the latest.
- `<hash|did>`: accepts either the 12-character BLAKE3 hash or the full DID string.

# Error handling

`KeyStoreError` is a dedicated error type, separate from `CryptoError`:

```rust
enum KeyStoreError {
    Io(std::io::Error),
    AlreadyExists(String),   // derived entry name
    NotFound(String),        // derived entry name
    Mismatch(String),        // derived entry name: did.txt contains a different DID
    HomeDirNotFound,
    Crypto(CryptoError),
}
```
