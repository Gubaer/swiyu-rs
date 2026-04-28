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

## `didtool log`

Read-only access to a DID's log file. Three subcommands: `list`, `show`, `entry`. Like
`didtool keystore`, these commands never mutate the log — log entries are written by
`didtool create` and (in future) `didtool update`.

### Source selectors

Each `log` subcommand reads the log from one of two sources:

| Flag | Value | Behavior |
|---|---|---|
| `--did <did-or-hash>` | full DID string **or** 12-character BLAKE3 hash | Resolves to a DID, derives the HTTPS URL where the log is served, performs an HTTPS `GET`. |
| `--input <path>` | local file path | Reads the JSONL log from disk. |

`--did` and `--input` are mutually exclusive. When neither is given, `--input ./did.jsonl` is
used (matches the default `--out` of `didtool create`).

The `<did-or-hash>` value follows the same resolution rule as `keystore show` and
`keystore export`: a 12-character all-hex string is looked up in the key store and the DID is
read from that entry's `did.txt`; anything else is parsed as a DID string directly. The HTTPS
URL is derived from the DID's domain and optional path segments —
`https://<domain>/<path>/did.jsonl`, or `https://<domain>/.well-known/did.jsonl` when no path
is present. Percent-encoded `%3A` in the domain segment decodes to `:` so ports are handled
correctly.

### `didtool log list [--did <did-or-hash> | --input <path>]`

Lists every entry in the log, one row per entry, in sequence order:

```
SEQ  VERSION-ID                                   VERSION-TIME              DEACT
  1  1-QmXyZ…                                     2026-04-27T08:11:42Z      no
  2  2-QmAbC…                                     2026-04-27T09:02:11Z      no
  3  3-QmDeF…                                     2026-04-30T14:55:00Z      yes
```

Columns:
- `SEQ` — 1-based sequence number (matches the prefix of `versionId`).
- `VERSION-ID` — the full `versionId` of the entry.
- `VERSION-TIME` — the `versionTime` of the entry.
- `DEACT` — `yes` when the entry's `parameters.deactivated` is `true`, else `no`.

### `didtool log show [--did <did-or-hash> | --input <path>] [--out <file>] [--raw | --pretty]`

Outputs the full DID log.

- Default (stdout): pretty-printed JSON, blank line between entries, each preceded by a
  comment line `# entry <seq> — <versionId>`. Both `did:tdw` v0.3 (five-element array) and
  `did:webvh` v1.0 (named-field object) render in their native shape.
- `--out <file>`: writes to a file. The default file format is **raw JSONL** — byte-equivalent
  to the source — so signatures and hashes still verify against the saved copy.
- `--raw`: forces raw JSONL output, even on stdout (suitable for piping into `jq`).
- `--pretty`: forces pretty-printed JSON, even when writing to a file.

`--raw` and `--pretty` are mutually exclusive.

### `didtool log entry [--did <did-or-hash> | --input <path>] [--at <selector>] [--out <file>] [--raw | --pretty]`

Outputs a single entry from the DID log. `--at <selector>` selects the entry:

| Selector      | Meaning |
|---------------|---------|
| `latest`      | The last entry in the log. This is the default when `--at` is omitted. |
| `<n>`         | The entry at 1-based index `<n>` (matches the sequence number prefix of `versionId`). |
| `<versionId>` | The entry whose `versionId` matches exactly. |

Output rules are identical to `log show`: pretty-printed JSON to stdout by default, raw JSONL
to file by default. `--raw` / `--pretty` override.

### HTTPS fetch behavior (when `--did` is used)

- Any non-2xx response status is a hard error; the status and a snippet of the response body
  are included in the error message on stderr.
- No specific `Content-Type` is required — the body is parsed line-by-line as JSONL.
- A 50 MiB cap on response size guards against runaway responses. This is far above any
  realistic DID log size. The cap can be raised by setting `DIDTOOL_LOG_MAX_BYTES` in the
  environment.
- The fetch is synchronous (`reqwest` blocking client), consistent with the `--swiyu` form of
  `didtool create`. No async runtime is introduced.

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
`identifierRegistryUrl` from the response as the DID URL. After the local DID log entry is
constructed and signed, it is uploaded back to the registry via a PUT request, completing the
registration in a single command. Use `--no-publish` to skip the upload step (e.g. for dry-run
testing). Requires `SWIYU_ACCESS_TOKEN` to be set in the environment — it is intentionally not
accepted as a flag to keep it out of shell history and process listings.

| Flag | Env var | Description |
|---|---|---|
| `--partner-id <id>` | `SWIYU_PARTNER_ID` | Business partner ID |
| `--registry-url <url>` | `SWIYU_IDENTIFIER_REGISTRY_URL` | Base URL of the identifier registry API |
| _(no flag)_ | `SWIYU_ACCESS_TOKEN` | Bearer token for the registry API; env var only |

The API calls made are:

```
1. POST <registry-url>/api/v1/identifier/business-entities/<partner-id>/identifier-entries
   Authorization: Bearer <access-token>

   Allocates a DID space. The response body contains `identifierRegistryUrl`
   of the form `https://identifier-reg.<env>.swiyu.admin.ch/api/v1/did/<id>`
   (the public path from which the DID log will be served, with `/did.jsonl`
   appended at resolution time). The `<id>` is a UUID that also appears as
   the last path segment of the resulting DID; it is used to address the
   entry in the next call.

2. PUT <registry-url>/api/v1/identifier/business-entities/<partner-id>/identifier-entries/<id>
   Authorization: Bearer <access-token>
   Content-Type: application/jsonl+json
   Body: <the DID log entry, one line of JSON, no trailing newline>

   Uploads the signed DID log entry. After this returns 2xx, the DID is
   resolvable via the `identifierRegistryUrl` from step 1.
```

#### Failure semantics

If the registry POST succeeds but the PUT fails, the registry has an allocated-but-empty entry
and the local files (`did.jsonl` + keystore entry) are written but not published. The CLI keeps
the local files (so the keys aren't lost), reports the error, and exits non-zero. **Re-running
`didtool create --swiyu` will allocate a fresh identifier and orphan the previous one** —
instead, retry the upload manually with the local `did.jsonl` (e.g. via `curl`). A `didtool
publish` subcommand to automate retry is not currently provided.

### Common options

| Option | Description |
|---|---|
| `--format tdw\|webvh` | DID method to use. Default: `webvh`. |
| `--out <file>` | Where to write the initial DID log. Default: `did.jsonl` in the current directory. |
| `--authorized-key <pem-file>` | Private EdDSA (Ed25519) key to use for the `authorized` role. Generated if omitted. |
| `--authentication-key <pem-file>` | Private ECDSA (P-256) key to use for the `authentication` role. Generated if omitted. |
| `--assertion-key <pem-file>` | Private ECDSA (P-256) key to use for the `assertion` role. Generated if omitted. |
| `--no-publish` | (with `--swiyu` only) skip the PUT upload step. The DID is created locally but not published to the registry. |

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
6. **For `--swiyu` (unless `--no-publish`)**: PUTs the DID log entry to the registry at the
   allocated identifier endpoint. On failure, the local files (DID log + keystore entry) are
   kept; the error message instructs the user to retry the upload manually.
7. Prints the DID to stdout.

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
| SWIYU API request failed               | 1         | `error: registry API error: HTTP <status>`                     |
| DID created locally but registry upload failed | 1 | `error: DID created and saved locally, but registry upload failed (HTTP <status>) — retry manually with the file at <path>` |
| Neither `<url>` nor `--swiyu` given    | 1         | `error: provide a <url> or --swiyu`                            |
| Both `<url>` and `--swiyu` given       | 1         | `error: <url> and --swiyu are mutually exclusive`              |
| Both `--did` and `--input` given       | 1         | `error: --did and --input are mutually exclusive`              |
| `--did` value is neither a DID nor a 12-char hex hash | 1 | `error: '<value>' is neither a DID nor a 12-character hex hash` |
| Hash given to `--did` not in key store | 1         | `error: no entry found for '<hash>'`                           |
| HTTPS fetch failed (network/DNS/TLS)   | 1         | `error: cannot fetch '<url>': <reason>`                        |
| HTTPS response is non-2xx              | 1         | `error: '<url>' returned <status>: <body>`                     |
| Response exceeds size cap              | 1         | `error: response from '<url>' exceeds <bytes> bytes`           |
| Log file is not valid JSONL            | 1         | `error: '<source>': line <n>: <parse error>`                   |
| `--at` selector matches no entry       | 1         | `error: no entry matches '<selector>'`                         |
| Both `--raw` and `--pretty` given      | 1         | `error: --raw and --pretty are mutually exclusive`             |

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
