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

### `didtool keystore show --did <did-or-hash> [--role authorized|authentication|assertion] [--version <n>]`

Displays public key(s) to stdout in PEM format.

- `--did <did-or-hash>` is required: accepts either the full DID string or its 12-character
  BLAKE3 hash.
- Without `--role`: displays all three public keys for the entry, each preceded by a comment
  line identifying the role (e.g. `# authorized`).
- With `--role`: displays only the public key for that role.
- `--version <n>`: selects a specific snapshot; defaults to the latest.

Private keys are never shown on stdout — use `export` for those.

### `didtool keystore export --did <did-or-hash> --role authorized|authentication|assertion --out <file> [--private] [--version <n>]`

Writes a single key to `--out` in PEM format.

- `--did <did-or-hash>` is required: accepts either the full DID string or its 12-character
  BLAKE3 hash.
- `--role` is required — one key is exported at a time.
- Without `--private`: exports the public key.
- `--private`: exports the private key. The explicit flag makes the intent clear and auditable
  in shell history.
- `--version <n>`: selects a specific snapshot; defaults to the latest.
- `--out <file>`: path to write the PEM file; required.

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

Lists every entry in the log, one row per entry, in sequence order. Output starts with a small
header identifying the DID, followed by a blank line and the entry rows:

```
DID:            did:tdw:QmXyZ…:example.com:dids:issuer
Keystore hash:  9a4964f818df

VERSION-ID                                   VERSION-TIME
1-QmXyZ…                                     2026-04-27T08:11:42Z
2-QmAbC…                                     2026-04-27T09:02:11Z
3-QmDeF…                                     2026-04-30T14:55:00Z
```

Header lines:
- `DID` — the DID this log belongs to. Taken from the `id` field of the latest entry's DID
  document.
- `Keystore hash` — the 12-character BLAKE3 hash of the local keystore entry for this DID, if
  one exists. The lookup is attempted for every source (`--did <did>`, `--did <hash>`,
  `--input <path>`, default). If no keystore entry exists, the line reads
  `Keystore hash:  (not in keystore)`.

Columns:
- `VERSION-ID` — the full `versionId` of the entry.
- `VERSION-TIME` — the `versionTime` of the entry.

### `didtool log show [--did <did-or-hash> | --input <path>] [--out <file>] [--force] [--raw | --pretty]`

Outputs the full DID log.

- Default (stdout): pretty-printed JSON, blank line between entries, each preceded by a
  comment line `# entry <seq> — <versionId>`. Both `did:tdw` v0.3 (five-element array) and
  `did:webvh` v1.0 (named-field object) render in their native shape.
- `--out <file>`: writes to a file. The default file format is **raw JSONL** — byte-equivalent
  to the source — so signatures and hashes still verify against the saved copy. If the file
  already exists the command refuses to overwrite it; pass `--force` to overwrite.
- `--raw`: forces raw JSONL output, even on stdout (suitable for piping into `jq`).
- `--pretty`: forces pretty-printed JSON, even when writing to a file.
- `--force`: only meaningful with `--out`; allows an existing file to be overwritten.

`--raw` and `--pretty` are mutually exclusive.

### `didtool log entry [--did <did-or-hash> | --input <path>] [--at <selector>] [--out <file>] [--force] [--raw | --pretty]`

Outputs a single entry from the DID log. `--at <selector>` selects the entry:

| Selector | Meaning |
|----------|---------|
| `latest` | The last entry in the log. This is the default when `--at` is omitted. |
| `<n>`    | The entry at 1-based numeric index `<n>` (matches the sequence-number prefix of `versionId`). |

Output rules are identical to `log show`: pretty-printed JSON to stdout by default, raw JSONL
to file by default. `--raw` / `--pretty` override. `--out <file>` refuses to overwrite an
existing file unless `--force` is given.

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

---

## `didtool update`

```
didtool update [--did <did-or-hash> | --input <path>]
               [--rotate authorized | --rotate authentication | --rotate assertion | --rotate all] ...
               [--authorized-key <pem-file>]
               [--authentication-key <pem-file>]
               [--assertion-key <pem-file>]
               [--out <file>] [--force]
               [--no-publish]
```

Appends a new entry to an existing DID log, rotating one or more keys. The new entry is signed
by the *current* authorized key (loaded from the key store), links back to the previous entry
via the entryHash chain, and embeds the new authentication / assertion keys in the DID
document.

At least one of `--rotate <role>`, `--authorized-key`, `--authentication-key`, or
`--assertion-key` must be present — otherwise there is nothing to update.

### Source

Same selectors as `didtool log`:

| Flag | Behavior |
|---|---|
| `--did <did-or-hash>` | Resolves to a DID (hash via key store, otherwise direct DID parse), fetches the existing log via HTTPS. |
| `--input <path>` | Reads the existing log from a local file. |
| _(neither)_ | Defaults to `--input ./did.jsonl`. |

`--did` and `--input` are mutually exclusive.

### Key rotation

Two kinds of flag, freely combinable across roles but **mutually exclusive per role**:

| Flag | Description |
|---|---|
| `--rotate <role>` | Generate a fresh key for `<role>`. The flag is repeatable; values are `authorized`, `authentication`, `assertion`, or `all` (= the three roles). Duplicate values are no-ops. |
| `--authorized-key <pem-file>` | Import an existing Ed25519 PEM as the new authorized key. |
| `--authentication-key <pem-file>` | Import an existing P-256 PEM as the new authentication key. |
| `--assertion-key <pem-file>` | Import an existing P-256 PEM as the new assertion key. |

Roles not addressed by either flag keep their current key — the entry still references them
unchanged. Combining `--rotate authorized` with `--authorized-key` (etc.) on the same role is an
error.

### Output

| Flag | Description |
|---|---|
| `--out <file>` | Write the **full updated log** to this path. |
| `--force` | Allow `--out` to overwrite an existing file. |
| _(no `--out`)_ | Append to the source file in place. The write is performed via a temporary file followed by an atomic rename, so a crash mid-write cannot corrupt the existing log. |

### Publish

| Flag | Description |
|---|---|
| `--no-publish` | Skip the registry update; produce only the local files. |

The SWIYU registry accepts updates via the **same call used by `create`**: a `PUT` to
`<registry-url>/api/v1/identifier/business-entities/<partner>/identifier-entries/<uuid>` with
`Content-Type: application/jsonl+json` and the **full updated log** as the body (genesis entry
+ all subsequent updates). The registry treats it as an idempotent replace; subsequent `GET`s
on the public DID URL serve the body byte-for-byte. The reference DID Toolbox (Java) does
*not* publish updates of any kind — its `update` command is purely local — so this behavior
is specific to the SWIYU registry, not the did:tdw spec.

The CLI does **not yet** make this call. `--no-publish` is currently the only behavior and the
flag is a no-op, accepted so the surface doesn't change when publish lands. Once implemented,
omitting `--no-publish` will PUT the updated log as described above; failure semantics will
mirror `create` (local files kept, error message instructing manual retry).

### What `update` does internally

1. Loads the existing DID log (from file or HTTPS).
2. Looks up the current authorized key pair in the key store by the log's DID. If no key store
   entry exists, fails with a clear error — the new entry cannot be signed without it.
3. Builds the staged key set: imports or generates per the rotation flags; keeps current keys
   for unrotated roles.
4. Constructs the new DID log entry:
   - `versionId` placeholder = the previous entry's `versionId` (this is the value substituted
     for the entryHash computation).
   - `versionTime` = `max(now − 5s, previous_versionTime + 1s)`, ISO-8601 UTC.
   - `parameters.updateKeys` updated only if the authorized key rotated.
   - `state.value` is the new DID document with the new authentication / assertion keys.
   - Computes `entryHash` over the 4-element entry (proof slot excluded), JCS-canonicalised;
     the final on-disk `versionId` is `"<n+1>-<entryHash>"`.
   - Signs with the *previous* authorized key; `proof.challenge` is the new `versionId`.
5. Commits the new key pairs to the key store at version `current+1`.
6. Writes the resulting log (atomic-rename to the source path, or to `--out` if given).
7. (Once publish is implemented) PUTs the updated log to the SWIYU registry. On failure the
   local files are kept; the error message instructs the user to retry manually.

### Failure semantics

If the key store lookup fails (DID not present, current authorized key unreadable), the
command aborts before any file is written.

If the new entry has been written locally but a future publish step fails, the local files
(DID log + new key store version) are kept, mirroring `create`.

### Out of scope for this version

- **Prerotation / `nextKeyHashes`.** did:tdw 0.3 supports pre-committing to a future authorized
  key. Not implemented yet. When added, `update` will enforce that the new authorized
  multikey hash matches any commitment recorded in the previous entry's `parameters`.
- **Non-key DID-document updates** (services, additional contexts, etc.) are not supported.
  `update` only rotates the three key roles.

---

## `didtool deactivate`

```
didtool deactivate [--did <did-or-hash> | --input <path>]
                   [--out <file>] [--force]
                   [--no-publish]
                   [--partner-id <id>] [--registry-url <url>]
```

Marks an existing DID as deactivated by appending a final entry to its log. Once deactivated,
the DID can still be resolved (its log is still served) but no further entries are valid —
resolvers and registries should treat it as terminated.

Deactivation is one-way. The command refuses to operate on a DID whose latest entry already
has `parameters.deactivated == true`.

### Source, output, publish

Identical to `didtool update`:

- `--did <did-or-hash>` / `--input <path>` (mutually exclusive; default `./did.jsonl`).
- `--out <file>` writes the full log; without it, the source file is updated atomically via
  temp-file-and-rename. `--force` allows `--out` to overwrite an existing file.
- `--no-publish` skips the registry PUT. With publish enabled (the default),
  `--partner-id` / `SWIYU_PARTNER_ID` and `--registry-url` / `SWIYU_IDENTIFIER_REGISTRY_URL`
  are required.

There are no key-rotation flags. Deactivation does not rotate any keys.

### What `deactivate` does internally

1. Loads the existing DID log (file or HTTPS).
2. Refuses if the latest entry's `parameters.deactivated` is already `true`.
3. Looks up the current authorized key pair in the key store by the log's DID. Required to
   sign the new entry.
4. Constructs the new DID log entry:
   - `versionId` placeholder = the previous entry's `versionId` (substituted for the
     `entryHash` computation).
   - `versionTime` = `max(now − 5s, previous_versionTime + 1s)`, ISO-8601 UTC.
   - `parameters` contains exactly two fields: `deactivated: true` and `updateKeys: []`. No
     other parameter fields are included.
   - `state.value` is the previous entry's DID document, **unchanged** — same keys, same
     contexts, same id. Deactivation is a state change, not a re-key.
   - Computes `entryHash` over the 4-element entry (proof slot excluded), JCS-canonicalised;
     final on-disk `versionId` is `"<n+1>-<entryHash>"`.
   - Signs with the current authorized key; `proof.challenge` is the new `versionId`.
5. Writes the resulting log (atomic-rename to the source path, or to `--out` if given).
6. (Unless `--no-publish`) PUTs the full updated log to the SWIYU registry, mirroring
   `update`. On failure the local files are kept; the error message instructs the user to
   retry manually.

The key store is **not** advanced to a new version: deactivation does not change any key
material, so no new snapshot is needed.

### Failure semantics

If the key store entry for the DID is missing, the command aborts before any file is
written — the deactivation entry cannot be signed without it.

If the local write succeeded but the registry PUT fails, the local file is kept; the user
can retry the upload manually with `curl` against the same `identifier-entries/<uuid>` path.

---

## `didtool create-pop`

```
didtool create-pop --did <did-or-hash>
                   [--role authorized | authentication | assertion]
                   [--nonce <string>]
                   [--ttl <seconds>]
                   [--out <file>] [--force]
```

Generates a Proof of Possession (PoP) JWT signed with one of the DID's keys. The resulting
JWT proves cryptographically that the caller controls the corresponding private key. Typical
uses are registry onboarding handshakes (where a verifier challenges the DID controller with
a nonce) and low-level testing.

### Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--did <did-or-hash>` | yes | — | Full DID string or 12-character BLAKE3 hash. Looked up in the key store. |
| `--role <role>` | no | `assertion` | Which key signs the PoP: `authorized`, `authentication`, or `assertion`. Determines the JWT `alg` (Ed25519 → `EdDSA`, P-256 → `ES256`) and the `kid` value. |
| `--nonce <string>` | no | _(auto-generated)_ | Value embedded in `payload.nonce`. When omitted, a 128-bit cryptographically random value is drawn from the OS CSPRNG, base64url-encoded (unpadded), and printed to stderr. For real verifier handshakes (registry onboarding, OID4VCI), pass the verifier-supplied challenge here instead of relying on auto-generation. |
| `--ttl <seconds>` | no | `3600` | Validity in seconds from now: `iat = now`, `exp = now + ttl`. Must be a positive integer; `--ttl 0` is rejected. |
| `--out <file>` | no | stdout | Write the JWT to a file instead of stdout. |
| `--force` | no | off | Allow `--out` to overwrite an existing file. |

### Resulting JWT

The signed JWT has this shape (header and payload shown decoded):

```
header:  { "alg": "EdDSA", "kid": "did:tdw:Q…:example.com#assert-key-01" }
payload: { "iss":   "did:tdw:Q…:example.com",
           "iat":   1714400000,
           "exp":   1714403600,
           "nonce": "Your Nonce" }
```

- `alg` is derived from the key type of the chosen role; never user-controllable (a forced
  mismatch would only produce JWTs no verifier can verify).
- `kid` is the full verification method id (DID + `#fragment`) of the role's key in the
  latest snapshot of the DID document.
- `iss` is the DID itself.
- `iat` / `exp` are Unix timestamps in seconds.

### Output

By default the JWT is written to stdout **without a trailing newline**, so shell redirection
produces a byte-exact JWT file:

```
$ didtool create-pop --did 0a1b2c3d4e5f --nonce abc > pop.jwt
```

When `--out` is used, the same byte-exact JWT is written to the file. The command refuses to
overwrite an existing `--out` target unless `--force` is given.

When `--nonce` is omitted, the auto-generated nonce is printed to **stderr** (one line,
prefixed `generated nonce: `) so the user can record it for later verification:

```
$ didtool create-pop --did 0a1b2c3d4e5f > pop.jwt
generated nonce: 7Q3vKx2NfL9aB1cD4eFgHi
```

### What `create-pop` does internally

1. Resolves `--did` to a key store entry (12-char hash or full DID).
2. Loads the latest snapshot of that entry: the DID, the role's private key, and the matching
   verification method id from the latest DID document.
3. Computes the JWT `kid` (verification method id) and `alg` (from the key type).
4. Generates a nonce if `--nonce` was not supplied.
5. Builds the JWT header and payload, base64url-encodes each, signs the
   `<header>.<payload>` signing input with the private key, and assembles the compact JWS.
6. Writes the JWT to stdout (no trailing newline) or to `--out`.

### Failure semantics

If the key store entry is missing, or the role's verification method cannot be found in the
latest DID-document snapshot, the command aborts before any output is produced.

### Out of scope for this version

- Selecting a key from a non-current snapshot (e.g. a rotated-out authorized key). v1 always
  uses the latest snapshot.
- OID4VCI-shaped proof JWTs (`typ: openid4vci-proof+jwt`, `aud` claim). A separate command,
  `create-cred-proof`, will cover that case.
- Reading the nonce from stdin or a file. Pass it via `--nonce <string>`.

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
| `--ttl` is zero or negative            | 1         | `error: --ttl must be a positive integer`                      |
| Role's verification method missing in latest snapshot | 1 | `error: no '<role>' verification method in latest snapshot`    |

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
