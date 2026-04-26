The `KeyStore` persists key pairs for generated DIDs on disk.

# Directory layout

```
<root>/
  <name>/
    authorized-private.pem      ← EdDSA (signs DID log entries)
    authorized-public.pem
    authentication-private.pem  ← ECDSA (DID authentication)
    authentication-public.pem
    assertion-private.pem       ← ECDSA (signs verifiable credentials)
    assertion-public.pem
    did.txt                     ← the full DID string
```

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

Each entry holds exactly three key pairs:

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

```rust
KeyStore::create(&self, did: &Did) -> Result<KeyStoreEntry, KeyStoreError>
```

Creates a new subdirectory for `did`, generates and persists all three key
pairs, and writes `did.txt`. Fails if an entry for this DID already exists.

```rust
KeyStore::lookup(&self, did: &Did) -> Result<Option<KeyStoreEntry>, KeyStoreError>
```

Computes the subdirectory name from `did`, checks whether it exists, reads
`did.txt` and verifies it matches `did`, then loads and returns the entry.
Returns `Ok(None)` if no subdirectory exists. Returns
`Err(KeyStoreError::Mismatch)` if the subdirectory exists but `did.txt`
contains a different DID (hash collision or corruption).

```rust
KeyStore::remove(&self, did: &Did) -> Result<(), KeyStoreError>
```

Removes the subdirectory for `did` and all its contents. Fails if no entry
for this DID exists.

```rust
KeyStore::exists(&self, did: &Did) -> bool
```

Returns `true` if a subdirectory for `did` exists.

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
