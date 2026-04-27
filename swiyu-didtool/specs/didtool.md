# didtool CLI

`didtool` is a command-line tool for managing `did:tdw` and `did:webvh` identities. It handles
key generation, DID creation and updates, and key store access.

# Configuration

## Global flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--keystore <path>` | `DIDTOOL_KEYSTORE` | `~/.didtool/keys` | Key store root directory |
| `--verbose` | — | off | Enable DEBUG-level log output to stderr |

Priority for `--keystore`: flag > `DIDTOOL_KEYSTORE` env var > default.

Example:

```
didtool --keystore /path/to/keys --verbose keystore list
```

# Subcommands

## `didtool keystore`

Read-only access to the key store. Keys are never inserted directly through the CLI — they
are created as a side effect of DID operations such as `didtool create` and `didtool update`.

### `didtool keystore list`

Lists all entries in the key store, one per line, sorted by hash:

```
3f7a2c91b04e  did:webvh:abc123:example.com
9b1d4e72f3a1  did:webvh:def456:other.example.com
```

Two-column output (hash, DID separated by two spaces) for easy `grep`/`awk` use.

### `didtool keystore show <hash|did> [--role authorized|authentication|assertion] [--version <n>]`

Displays public key(s) to stdout in PEM format.

- Without `--role`: displays all three public keys for the entry, each preceded by a comment
  line identifying the role (e.g. `# authorized`).
- With `--role`: displays only the public key for that role.
- `--version <n>`: selects a specific snapshot; defaults to the latest.
- `<hash|did>`: accepts either the 12-character BLAKE3 hash or the full DID string.

Private keys are never shown on stdout — use `export` for those.

### `didtool keystore export <hash|did> --role authorized|authentication|assertion --out <file> [--private] [--version <n>]`

Writes a single key to `--out` in PEM format.

- `--role` is required — one key is exported at a time.
- Without `--private`: exports the public key.
- `--private`: exports the private key. The explicit flag makes the intent clear and auditable
  in shell history.
- `--version <n>`: selects a specific snapshot; defaults to the latest.
- `--out <file>`: path to write the PEM file; required.
- `<hash|did>`: accepts either the 12-character BLAKE3 hash or the full DID string.

## `didtool create`

Creates a new DID, generates (or imports) key pairs, writes the initial DID log, and stores the
keys in the key store.

The URL that becomes part of the DID can be supplied in two ways — exactly one must be provided.

### Form 1 — explicit URL

```
didtool create <url> [options]
```

`<url>` is the HTTPS URL where the DID log will be served
(e.g. `https://example.com/.well-known/did.jsonl`). The domain and path components are extracted
to form the DID identifier.

### Form 2 — SWIYU partner

```
didtool create --swiyu [--partner-id <id>] [--registry-url <url>] [options]
```

Calls the SWIYU identifier registry API to allocate a new DID space, then uses the
`identifierRegistryUrl` from the response as the DID URL. Requires `SWIYU_ACCESS_TOKEN` to be
set in the environment — it is intentionally not accepted as a flag to keep it out of shell
history and process listings.

| Flag | Env var | Description |
|---|---|---|
| `--partner-id <id>` | `SWIYU_PARTNER_ID` | Business partner ID |
| `--registry-url <url>` | `SWIYU_IDENTIFIER_REGISTRY_URL` | Base URL of the identifier registry API |
| _(no flag)_ | `SWIYU_ACCESS_TOKEN` | Bearer token for the registry API; env var only |

The API call made is:

```
POST <registry-url>/api/v1/identifier/business-entities/<partner-id>/identifier-entries
Authorization: Bearer <access-token>
```

### Common options

| Option | Description |
|---|---|
| `--format tdw\|webvh` | DID method to use. Default: `webvh`. |
| `--out <file>` | Where to write the initial DID log. Default: `did.jsonl` in the current directory. |
| `--authorized-key <pem-file>` | Private EdDSA (Ed25519) key to use for the `authorized` role. Generated if omitted. |
| `--authentication-key <pem-file>` | Private ECDSA (P-256) key to use for the `authentication` role. Generated if omitted. |
| `--assertion-key <pem-file>` | Private ECDSA (P-256) key to use for the `assertion` role. Generated if omitted. |

When a private key file is supplied, the public key is derived from it — no separate public key
file is needed. Key pairs not supplied by the user are generated fresh.

Constraints on supplied keys:
- `--authorized-key` must be an Ed25519 private key.
- `--authentication-key` and `--assertion-key` must each be a P-256 private key.
- `--authentication-key` and `--assertion-key` must be different keys.

A constraint violation produces a clear error before any keys are written to the key store or
the DID log is written to disk.

### Output

On success, the full DID string is printed to stdout:

```
$ didtool create https://example.com/.well-known/did.jsonl
did:webvh:Qm…:example.com
```

A confirmation line (log file path, key store hash) is printed to stderr.

### What `create` does internally

1. Generates or reads the three private keys; derives the public keys.
2. Builds the genesis DID document from the public keys and the URL.
3. Derives the SCID and constructs the full DID.
4. Writes the initial DID log entry to `--out`.
5. Commits the keys to the key store.
6. Prints the DID to stdout.

### Dependencies

The `--swiyu` form requires an HTTP client (`reqwest`), which is an unconditional dependency.
`didtool` is a standalone CLI with no downstream consumers, so a feature flag to opt out would
add complexity without benefit.

`reqwest` is used in blocking mode — there is only one HTTP call and no concurrency needed, so
introducing an async runtime (tokio) would be unnecessary complexity for a CLI tool.

# Output conventions

- Normal output (key material, lists) goes to **stdout**.
- Error messages go to **stderr**.
- The process exits with code `0` on success, non-zero on failure.
- PEM is the only key output format.

# Error handling

Errors are reported as a single human-readable message on stderr followed by a non-zero exit
code. No stack traces or internal details are shown to the user.

| Condition                              | Exit code | Message                                                        |
|----------------------------------------|-----------|----------------------------------------------------------------|
| Entry not found in key store           | 1         | `error: no entry found for '<hash|did>'`                       |
| Ambiguous hash prefix (future)         | 1         | `error: ambiguous hash '<hash>'`                               |
| Key store directory not accessible     | 1         | `error: cannot open key store: <io error>`                     |
| Home directory not found               | 1         | `error: cannot resolve home directory`                         |
| I/O error writing export file          | 1         | `error: cannot write '<file>': <io error>`                     |
| Wrong key type for role                | 1         | `error: --<role>-key: expected <expected> key, got <actual>`   |
| authentication and assertion keys identical | 1    | `error: --authentication-key and --assertion-key must differ`  |
| SWIYU_ACCESS_TOKEN not set             | 1         | `error: SWIYU_ACCESS_TOKEN is not set`                         |
| SWIYU API request failed               | 1         | `error: registry API error: <status> <body>`                   |
| Neither `<url>` nor `--swiyu` given    | 1         | `error: provide a <url> or --swiyu`                            |
| Both `<url>` and `--swiyu` given       | 1         | `error: <url> and --swiyu are mutually exclusive`              |

# Logging

`tracing` and `tracing-subscriber` are used for diagnostic output. A global `--verbose` flag
controls the log level:

- **Default (no flag):** no log output. Errors are reported via `error: …` on stderr and a
  non-zero exit code, as described above.
- **`--verbose`:** enables `DEBUG`-level output to stderr. One line per meaningful step,
  prefixed with `DEBUG`.

Example:

```
$ didtool create https://example.com/.well-known/did.jsonl \
    --authorized-key ./my-key.pem --verbose
DEBUG imported authorized Ed25519 key from ./my-key.pem
DEBUG derived authorized public key
DEBUG generated authentication P-256 key pair
DEBUG generated assertion P-256 key pair
DEBUG built genesis DID document
DEBUG derived SCID
DEBUG wrote DID log to did.jsonl
DEBUG committed keys to key store (hash: 3f7a2c91b04e)
did:webvh:Qm…:example.com
```

`--verbose` is a global flag and applies to all subcommands. For the `keystore` subcommands it
surfaces steps such as which directory a key was loaded from.
