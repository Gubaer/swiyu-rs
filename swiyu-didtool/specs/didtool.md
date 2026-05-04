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

### `didtool keystore versions --did <did-or-hash>`

Lists all key-pair sets ("versions") stored for a single DID, one per line, sorted by
version number ascending:

```
1  initial
2  authorized authentication assertion
3  authorized
```

Each line is `<version>  <change-tag>` separated by two spaces. The change tag is either:

- `initial` — for version 1, which has no predecessor to compare against.
- a space-separated list of role names (`authorized`, `authentication`, `assertion`) whose
  public key differs from the immediately previous version. Roles whose key was kept are
  omitted. The order is fixed: authorized, authentication, assertion (so output is stable
  and greppable).

Two-column output mirrors `keystore list`. `--did` accepts either the full DID string or
its 12-character BLAKE3 hash, following the same resolution rule as `keystore show` and
`keystore export`.

This command is purely a key-store view — it does not consult the DID log. The version
numbers are the same ones used by `keystore show --version <n>` and
`keystore export --version <n>`.

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

VERSION-ID                                   VERSION-TIME          DEACTIVATED
1-QmXyZ…                                     2026-04-27T08:11:42Z  no
2-QmAbC…                                     2026-04-27T09:02:11Z  no
3-QmDeF…                                     2026-04-30T14:55:00Z  yes
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
- `DEACTIVATED` — `yes` if the entry's `parameters.deactivated` is `true`, `no` otherwise.
  did:tdw 0.3 only writes `deactivated: true` on the deactivation entry itself; earlier
  entries omit the field and read as `no`. Deactivation is one-way, so at most one row can
  read `yes` and it is always the last entry.

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
- A 1 MiB cap on response size guards against runaway responses. This is generous
  compared to realistic data (DID logs in the hundreds of KB; trust statements and
  status lists in the tens of KB) and applies to every HTTPS fetch didtool performs
  (DID log, trust registry, status list). The cap is fixed — there is no override.
- The fetch is synchronous (`reqwest` blocking client), consistent with the registry calls
  made by `didtool create`. No async runtime is introduced.

## `didtool create`

```
didtool create [--partner-id <id>] [--registry-url <url>] [--no-publish] [options]
```

Creates a new DID via the SWIYU identifier registry, generates (or imports) key pairs, writes
the initial DID log, stores the keys in the key store, and (unless `--no-publish`) publishes
the DID log to the registry.

Calls the SWIYU identifier registry API to allocate a new DID space, then uses the
`identifierRegistryUrl` from the response as the DID URL. After the local DID log entry is
constructed and signed, it is uploaded back to the registry via a PUT request, completing the
registration in a single command. Use `--no-publish` to skip the PUT (e.g. for dry-run
testing) — the POST that allocates the DID space still runs, since the URL must exist before
the SCID and proof can be computed. Requires `SWIYU_ACCESS_TOKEN` to be set in the
environment — it is intentionally not accepted as a flag to keep it out of shell history and
process listings.

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
`didtool create` will allocate a fresh identifier and orphan the previous one** — instead,
retry the upload manually with the local `did.jsonl` (e.g. via `curl`). A `didtool publish`
subcommand to automate retry is not currently provided.

### Common options

| Option | Description |
|---|---|
| `--format tdw\|webvh` | DID method to use. Default: `tdw` — the only method currently testable end-to-end against the SWIYU integration registry. `webvh` code paths exist but are not registry-validated. |
| `--out <file>` | Where to write the initial DID log. Default: `did.jsonl` in the current directory. |
| `--authorized-key <pem-file>` | Private EdDSA (Ed25519) key to use for the `authorized` role. Generated if omitted. |
| `--authentication-key <pem-file>` | Private ECDSA (P-256) key to use for the `authentication` role. Generated if omitted. |
| `--assertion-key <pem-file>` | Private ECDSA (P-256) key to use for the `assertion` role. Generated if omitted. |
| `--no-publish` | Skip the PUT upload step. The DID is allocated and signed locally but not published to the registry. |

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
$ didtool create
Generated DID: did:tdw:Qm…:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:<uuid>
Saved DID log entry: did.jsonl
Keystore hash: <12-char hash>
Published to registry: https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/<uuid>/did.jsonl
```

The `Published to registry:` line is omitted when `--no-publish` is given.

### What `create` does internally

1. POSTs to the SWIYU registry to allocate a DID space; the response yields the
   `identifierRegistryUrl` that becomes the DID's URL.
2. Generates or reads the three private keys; derives the public keys.
3. Builds the genesis DID document from the public keys and the URL.
4. Derives the SCID and constructs the full DID.
5. Writes the initial DID log entry to `--out`.
6. Commits the keys to the key store.
7. **Unless `--no-publish`**: PUTs the DID log entry to the registry at the allocated
   identifier endpoint. On failure, the local files (DID log + keystore entry) are kept; the
   error message instructs the user to retry the upload manually.
8. Prints the DID and a publish confirmation (or omits the publish line under `--no-publish`)
   to stdout.

### Dependencies

`create` requires an HTTP client (`reqwest`), which is an unconditional dependency. `didtool`
is a standalone CLI with no downstream consumers, so a feature flag to opt out would add
complexity without benefit.

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
| `--did <did-or-hash>` | Resolves to a DID (hash via key store, otherwise direct DID parse), fetches the existing log via HTTPS. The log is treated as a transient input — no local log file is read or written unless `--out` is given. |
| `--input <path>` | Reads the existing log from a local file. |
| _(neither)_ | Defaults to `--input ./did.jsonl`. |

`--did` and `--input` are mutually exclusive. When `--did` is used, any `did.jsonl` in the working directory is ignored — the registry copy is the source of truth.

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
| _(no `--out`, with `--input` or default)_ | Append to the source file in place via temp-file-and-rename, so a crash mid-write cannot corrupt the existing log. |
| _(no `--out`, with `--did`)_ | The new log is **not** written to any local file. Persistence relies on the registry publish — see *Publish* below. |

### Publish

| Flag | Description |
|---|---|
| `--no-publish` | Skip the registry update; produce only the local files. |

When publish is enabled (the default), the SWIYU registry is updated via the **same call used
by `create`**: a `PUT` to
`<registry-url>/api/v1/identifier/business-entities/<partner>/identifier-entries/<uuid>` with
`Content-Type: application/jsonl+json` and the **full updated log** as the body (genesis entry
+ all subsequent updates). The registry treats it as an idempotent replace; subsequent `GET`s
on the public DID URL serve the body byte-for-byte. The reference DID Toolbox (Java) does
*not* publish updates of any kind — its `update` command is purely local — so this behavior
is specific to the SWIYU registry, not the did:tdw spec.

When `--did` is used without `--out`, the registry is the **only** persistence path for the
new entry. Combining `--did`, no `--out`, and `--no-publish` is therefore rejected — the new
log entry would have nowhere to go.

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
6. If a local target is in scope (`--out`, or `--input`/default file with no `--out`), writes
   the resulting log atomically. With `--did` and no `--out`, this step is skipped.
7. (Unless `--no-publish`) PUTs the updated log to the SWIYU registry.

### Failure semantics

If the key store lookup fails (DID not present, current authorized key unreadable), the
command aborts before any file or registry write.

If a local log file was written and the registry publish then fails, the local file holds the
new entry; the error message instructs the user to retry manually.

If `--did` was used without `--out` (registry-only persistence) and publish fails, the new
log entry is salvaged to a fallback file `did-pending-<N>.jsonl` in the current directory,
where `<N>` is the lowest free positive integer. The error message points at this file so the
user can retry the upload manually. The key store has already advanced to the new version, so
the fallback file is the only record of the new entry's DID-document state outside the
key store.

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

- `--did <did-or-hash>` / `--input <path>` (mutually exclusive; default `./did.jsonl`). With
  `--did`, the registry copy is the source of truth and any local `did.jsonl` is ignored.
- `--out <file>` writes the full log; with `--input` (or default) and no `--out`, the source
  file is updated atomically via temp-file-and-rename. `--force` allows `--out` to overwrite
  an existing file. With `--did` and no `--out`, no local log file is written and persistence
  relies on the registry publish.
- `--no-publish` skips the registry PUT. With publish enabled (the default),
  `--partner-id` / `SWIYU_PARTNER_ID` and `--registry-url` / `SWIYU_IDENTIFIER_REGISTRY_URL`
  are required. Combining `--did`, no `--out`, and `--no-publish` is rejected — the new
  entry would have nowhere to go.

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
5. If a local target is in scope (`--out`, or `--input`/default file with no `--out`), writes
   the resulting log atomically. With `--did` and no `--out`, this step is skipped.
6. (Unless `--no-publish`) PUTs the full updated log to the SWIYU registry, mirroring
   `update`.

The key store is **not** advanced to a new version: deactivation does not change any key
material, so no new snapshot is needed.

### Failure semantics

If the key store entry for the DID is missing, the command aborts before any file or
registry write — the deactivation entry cannot be signed without it.

If a local log file was written and the registry PUT then fails, the local file holds the
deactivation entry; the user can retry the upload manually with `curl` against the same
`identifier-entries/<uuid>` path.

If `--did` was used without `--out` and publish fails, the deactivation entry is salvaged to
a fallback file `did-pending-<N>.jsonl` in the current directory, where `<N>` is the lowest
free positive integer. The error message points at this file so the user can retry the upload
manually.

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

---

## `didtool verify-pop`

```
didtool verify-pop [--jwt <string> | --jwt-file <path>]
                   [--did <hash-or-did> | --input <log-file>]
                   [--nonce <expected>]
                   [--allow-expired]
```

Verifies a Proof of Possession JWT: parses it, resolves the verifying key, checks the
signature, and validates the payload claims (`iss`, `exp`, `iat`, optionally `nonce`).
Symmetric with `create-pop`: a JWT produced by `create-pop` round-trips through `verify-pop`.

### Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--jwt <string>` | one of these two | — | The JWT to verify, passed inline. |
| `--jwt-file <path>` | one of these two | — | Path to a file containing the JWT. Useful when the JWT is too long for the command line, or when scripting. Mutually exclusive with `--jwt`. |
| `--did <hash-or-did>` | no | — | 12-character BLAKE3 hash *or* full DID. Resolves to an HTTPS URL and fetches the DID log via the same code path as `log show --did`. Mutually exclusive with `--input`. |
| `--input <path>` | no | — | Read the DID log from a local file. Mutually exclusive with `--did`. |
| `--nonce <string>` | no | — | If present, `payload.nonce` must equal this exactly. Without it, the nonce is reported but not enforced. |
| `--allow-expired` | no | off | Skip the `exp` freshness check. By default, JWTs whose `exp` is at or before the current time are rejected. |

### kid resolution

The `kid` in the JWT header takes one of two shapes:

- **`did:key:<multikey>#<multikey>`** — the kid encodes the verifying key directly. The
  multikey decodes to an Ed25519 public key (P-256 reserved). The `iss` cross-check and the
  multikey-vs-`updateKeys` check depend on whether `--did` / `--input` is supplied:

  - **Without `--did` / `--input`**: signature is verified self-contained, and `payload.iss`
    is reported but **not** cross-checked. The verifier is responsible for any out-of-band
    identity binding (e.g. checking the multikey against a registry record).
  - **With `--did` / `--input`**: the log is loaded; the kid's multikey **must** appear in
    the latest entry's `parameters.updateKeys`, and `payload.iss` **must** equal the log's
    DID. This binds the PoP to a specific DID's update authority.

- **`<did>#<fragment>`** — references a verification method inside a DID document. The
  document is resolved in priority order:

  1. **`--did <hash-or-did>`**: HTTPS fetch via the standard `log show` code path.
  2. **`--input <path>`**: read from the given local log file.
  3. **Default (no flag)**: look up the kid's DID in the local key store; map known
     fragments (`authentication-key-01` → Authentication, `assertion-key-01` → Assertion)
     to the corresponding role's stored public key.

  In all three branches, the DID derived from the resolved log/keystore must equal the DID
  part of the kid. `payload.iss` must equal the kid's DID.

### Validation order

Checks run fail-closed in this order; the first failure aborts:

1. JWT structurally well-formed: three dot-separated base64url parts; header and payload
   decode to JSON objects; signature decodes to bytes.
2. `header.alg` is one of `EdDSA` or `ES256`. **`alg: "none"` and any other algorithm are
   rejected.**
3. `header.kid` parses into one of the two supported shapes.
4. **kid resolution** per the chain above. For `did:key` kids with `--did`/`--input`, this
   includes verifying the multikey is in the log's `parameters.updateKeys`.
5. `header.alg` matches the resolved key type (`EdDSA` ↔ Ed25519, `ES256` ↔ P-256).
6. The signature verifies over `<base64url-header>.<base64url-payload>` with the resolved
   verifying key.
7. `iss` cross-check:
    - For `<did>#<fragment>` kids: `payload.iss == kid_did`.
    - For `did:key` kids with `--did`/`--input`: `payload.iss == log_did`.
    - For `did:key` kids without `--did`/`--input`: skipped (informational only).
8. Unless `--allow-expired`: `payload.exp > now` (Unix seconds).
9. `payload.iat <= now + 60` (a 60-second clock-skew tolerance).
10. If `--nonce <expected>` is given: `payload.nonce == expected`.

The cross-check at step 7 prevents *confused-deputy* errors: a JWT signed with key K bound
to DID A but claiming `iss = B` would otherwise let a verifier inadvertently vouch for B's
identity. For `<did>#<fragment>` kids the binding is intrinsic (kid encodes the DID); for
`did:key` kids, the binding requires looking up the log — which is why `iss` enforcement
for `did:key` only kicks in when a log source is provided.

### Output

#### Success

A multi-line summary on **stdout**, exit code 0:

```
PoP is valid
  alg:    EdDSA
  kid:    did:key:z6MktdAr3iUReU7HsCf7JnoCjQ5urpKTxZSC49KnjEVsA5CA
  iss:    did:tdw:Qmb7…:example.com
  iat:    2026-04-29T18:23:00Z
  exp:    2026-04-29T19:23:00Z (in 59m 30s)
  nonce:  bqjNtL55MStkosme9a4kMg
```

When `--allow-expired` is in effect and the JWT is past `exp`, the `exp` line reads
`expired 1h 12m ago`.

#### Failure

A single-line `error: …` on **stderr**, exit code 1. The message identifies the first failed
check; the JWT is treated as invalid as soon as any check fails.

### What `verify-pop` does internally

1. Reads the JWT from `--jwt` or `--jwt-file`.
2. Parses and base64url-decodes the three segments.
3. Validates `header.alg` against the supported set (`EdDSA`, `ES256`).
4. Parses `header.kid`; resolves the verifying key via the chain above.
5. Verifies the signature over the signing input (`<header>.<payload>`).
6. Cross-checks `iss` against the kid's DID, then enforces `exp` (unless `--allow-expired`)
   and `iat`.
7. If `--nonce` was given, compares to `payload.nonce`.
8. Prints the success summary to stdout.

### Failure semantics

`verify-pop` is read-only: no files are modified, no network calls beyond what `--did`
triggers. A failed verification simply produces an error and a non-zero exit code; no state
is left behind.

### Out of scope for this version

- HTTPS fetch outside the `--did` path (no resolver for kids that embed a DID we don't
  know about and that wasn't passed via `--did` / `--input`).
- Algorithms beyond `EdDSA` and `ES256`. RSA, secp256k1, etc. are rejected with
  `UnsupportedAlg`.
- DPoP-specific headers (`htu`, `htm`, `ath`).
- A `--quiet` mode that suppresses the success summary. Add later if scripting demands it.

---

## `didtool business-entity`

Read-only access to the SWIYU **trust registry**: the service that holds
`TrustStatementIdentityV1` statements asserting facts about registered SWIYU business
entities (legal name in each language, state-actor flag, etc.). The trust registry is a
distinct service from the identifier (DID) registry — see the URL anatomy below.

The current subcommand list:

| Subcommand | Purpose |
|---|---|
| `lookup` | Fetch and display trust statements for a business entity. **Does not** verify signatures or revocation. |
| `verify-trust` | Fetch, then perform full verification: issuer allowlist, signature, freshness, revocation. |

### `didtool business-entity lookup`

```
didtool business-entity lookup --did <did-or-hash>
                               [--trust-registry-url <url>]
                               [--raw]
```

Fetches the trust statements for a business entity DID from the SWIYU trust registry,
decodes them, and displays the disclosed claims. **Display only** — the JWT signatures
are not verified. For trust assertions, use `verify-trust`.

#### Flags

| Flag | Env var | Required | Default | Description |
|---|---|---|---|---|
| `--did <did-or-hash>` | — | yes | — | Subject DID. Full DID string or 12-character BLAKE3 hash; the hash form is resolved via the local key store and is convenient for looking up your *own* business entity during development. |
| `--trust-registry-url <url>` | `SWIYU_TRUST_REGISTRY_URL` | one of these | — | Base URL of the SWIYU trust registry (e.g. `https://trust-reg.trust-infra.swiyu-int.admin.ch`). Environment-specific (int / pre-prod / prod). At least one of the flag or the env var must be set. |
| `--raw` | — | no | off | Emit the registry response (JSON array of SD-JWT VC strings) verbatim to stdout, pretty-printed. Useful for piping to `jq` or saving the original artifact. |

#### Endpoint

The CLI sends a single GET to:

```
<trust-registry-url>/api/v1/truststatements/identity/<percent-encoded-DID>
```

Only `:` characters in the DID are percent-encoded (to `%3A`); other DID characters are
already URL-safe. The endpoint is public — no `Authorization` header is sent. Response
is expected to be a JSON array of SD-JWT VC strings.

The path segment `identity` is hardcoded; this command does not query other trust
statement types. If/when SWIYU adds others, they will surface as separate subcommands or
a `--type` flag.

#### Default output

For one or more statements, sorted newest-first by `iat`:

```
Trust statements for did:tdw:QmPAaz…:fce949f2-…

#1  TrustStatementIdentityV1
  issuer:       did:tdw:QmWrXW…:2e246676-…
  iat:          2026-04-19T12:32:18Z
  nbf:          2026-01-01T00:00:00Z
  exp:          2026-12-31T20:00:00Z
  entity name:  de-CH: kacon GmbH
                fr-CH: kacon Sàrl
                it-CH: kacon Sagl
  state actor:  no
  status:       SwissTokenStatusList-1.0 idx=643
                https://status-reg.trust-infra.swiyu-int.admin.ch/api/v1/statuslist/ad94b60b-….jwt
```

- `entity name` shows **all** locales present in the disclosed `entityName` map, sorted
  alphabetically by language tag. Empty maps are rendered as `(none)`.
- `state actor` renders booleans as `yes` / `no`.
- The header line shows the queried DID once; the per-statement `sub` claim is not
  repeated (it's identical to the queried DID by definition for `identity` statements).

For zero statements: a single line on **stderr** (so stdout is still empty for piping):

```
no trust statements found for <did>
```

#### `--raw` output

The registry response, pretty-printed:

```json
[
  "eyJ2ZXIiOiIxLjAi…~WyJ…~WyJ…~WyJ…~"
]
```

Compact-print is not offered; consumers who need it can pipe through `jq -c .`.

#### Exit codes

| Code | Meaning |
|---|---|
| `0` | One or more trust statements were returned and decoded successfully. |
| `1` | The registry returned an empty array, or a `404` for the DID. **Semantically**: the entity is not vouched for by the SWIYU trust authorities. The DID may exist in the identifier registry but have no trust statement. |
| `2` | Operational error: bad config, network failure, non-`404` non-`2xx` response, or malformed/undecodable trust statement. |

The split lets scripts distinguish "this entity is untrusted" (`1`) from "I couldn't tell"
(`2`). Pattern:

```sh
if didtool business-entity lookup --did "$DID" >/dev/null 2>&1; then
    echo "trusted"
else
    case $? in
        1) echo "untrusted (no statements)" ;;
        2) echo "could not check (operational error)" ;;
    esac
fi
```

#### What `lookup` does internally

1. Resolves `--did` to a DID string (parses directly, or looks up a 12-char hash via the
   key store).
2. Resolves `--trust-registry-url` from the flag or `SWIYU_TRUST_REGISTRY_URL`.
3. Sends `GET <base>/api/v1/truststatements/identity/<encoded-did>`.
4. Parses the response as a JSON array of strings; each string as an SD-JWT VC.
5. For each VC: decodes header, payload, and disclosures (no signature check); pulls
   `entityName`, `isStateActor`, `iss`, `iat`, `nbf`, `exp`, `vct`, and `status.status_list`
   for display.
6. Sorts by `iat` descending; renders one block per statement.

#### Out of scope for this version

- Signature verification (deferred to `verify-trust`).
- Revocation/status-list checks (deferred to `verify-trust`).
- Filtering by statement type — `identity` is hardcoded.
- Pagination. Trust statements per entity are expected to be a small handful; no
  `?limit` / `?offset` handling.
- Caching. Each invocation hits the registry.
- Authentication. The endpoint is public; `SWIYU_ACCESS_TOKEN` is not used.

### `didtool business-entity verify-trust`

```
didtool business-entity verify-trust --did <did-or-hash>
                                     [--trust-registry-url <url>]
                                     [--trust-issuer <did>]
```

Fetches trust statements for a business entity DID and runs full verification on each:
issuer allowlist, signature, freshness, revocation. Reports a per-statement verdict and
an overall trust verdict for the entity.

The overall verdict is **trusted** iff at least one statement passes all checks —
matching the question "is this entity currently vouched-for by SWIYU right now?".

#### Flags

| Flag | Env var | Required | Description |
|---|---|---|---|
| `--did <did-or-hash>` | — | yes | Subject DID. Same resolution as `lookup`. |
| `--trust-registry-url <url>` | `SWIYU_TRUST_REGISTRY_URL` | one of these | Base URL of the SWIYU trust registry. Same as `lookup`. |
| `--trust-issuer <did>` | `SWIYU_TRUST_ISSUER_DID` | one of these | The well-known SWIYU trust authority's DID. Used as an allowlist for `payload.iss`. Also used to verify the *status list's* signature, since SWIYU signs both the trust statement and the status list with the same DID. |

#### Validation per statement

Each statement is verified independently. The five checks (in order):

1. **Issuer allowlist**: `payload.iss == --trust-issuer`.
2. **Issuer DID resolution**: fetch the issuer's `did.jsonl` from the identifier registry
   (the URL is encoded in the DID — `did:tdw:Q…:identifier-reg.…:api:v1:did:UUID` resolves
   to `https://identifier-reg.…/api/v1/did/UUID/did.jsonl`). Find the verification method
   whose id equals the JWT's `kid`.
3. **Signature**: verify the SD-JWT VC's JWS over `<header>.<payload>` with the resolved
   key. **Short-circuit**: if this fails, `freshness` and `status` are still reported but
   `iss` and `signature` failures cause the statement's verdict to be untrusted.
4. **Freshness**: `nbf ≤ now ≤ exp` (Unix seconds). Independent of signature.
5. **Revocation (status list)**:
   1. Fetch the JWT at `status.status_list.uri`.
   2. Verify *its* signature against `--trust-issuer` (SWIYU signs the status list
      with the same DID — confirmed empirically against the integration environment).
   3. Read `payload.status_list.bits` (default `1`; observed `2` in SWIYU integration).
   4. Decompress `payload.status_list.lst` (zlib-deflate, base64url-encoded).
   5. Read the value at `status.status_list.idx` from the bitstring.
   6. `0` = valid; non-zero = revoked / suspended / reserved (all treated as untrusted).

A statement is **trusted** iff all five checks pass.

The overall command verdict is **trusted** iff at least one statement is trusted.

#### Status-list value semantics

For 2-bit entries (the SWIYU default), the value at the indexed position is interpreted
per the IETF Token Status List draft:

| Value | Label | Treated as |
|---|---|---|
| `0` | valid | trusted |
| `1` | revoked | untrusted |
| `2` | suspended | untrusted |
| `3` | reserved | untrusted (defensive) |

For 1-bit entries (legacy fallback): `0` = valid, `1` = revoked.

#### Default output

```
Trust statements for did:tdw:QmPAaz…:fce949f2-…
Expected issuer:    did:tdw:QmWrXW…:2e246676-…

#1  TrustStatementIdentityV1
  iat:          2026-04-20T11:12:18Z
  iss:          [ok]    matches expected issuer
  signature:    [ok]    valid (kid: did:tdw:…#assert-key-02)
  freshness:    [ok]    now within nbf..exp (2026-01-01..2027-01-01)
  status:       [ok]    valid (idx=643, bits=2)
  entity name:  de-CH: kacon GmbH
  state actor:  no
  verdict:      [ok]    trusted

Verdict: 1 trusted statement out of 1 — entity is trusted.
```

Failure example (issuer mismatch):

```
#1  TrustStatementIdentityV1
  iat:          2026-04-20T11:12:18Z
  iss:          [fail]  did:tdw:OTHER… (does not match expected issuer)
  signature:    [skip]  (issuer mismatch)
  freshness:    [ok]    now within nbf..exp
  status:       [skip]  (would only matter if signature were trusted)
  verdict:      [fail]  untrusted

Verdict: 0 trusted statements out of 1 — entity is untrusted.
```

Markers:

| Marker | Meaning |
|---|---|
| `[ok]` | Check passed. |
| `[fail]` | Check failed; reason printed inline. |
| `[skip]` | Check skipped because an earlier check made it meaningless (e.g. signature skipped after issuer mismatch). |

#### Exit codes

| Code | Meaning |
|---|---|
| `0` | At least one statement passes all checks — entity is trusted. |
| `1` | Zero trust statements, or none of the statements pass all checks. **Semantically untrusted.** |
| `2` | Operational error: bad config, network failure, malformed JWT, can't resolve issuer DID, can't reach status list, etc. Not a verdict — "we couldn't tell". |

#### What `verify-trust` does internally

1. Resolves `--did`, `--trust-registry-url`, `--trust-issuer` (flag or env).
2. Fetches trust statements (same `lookup` code path).
3. For each statement:
   1. Decodes header / payload / disclosures.
   2. Cross-checks `iss` against `--trust-issuer`.
   3. Resolves the issuer DID's log via the identifier registry, locates the
      verification method by `kid`.
   4. Verifies the JWS signature.
   5. Checks `nbf ≤ now ≤ exp`.
   6. Fetches the status-list JWT, verifies its signature with `--trust-issuer`,
      decompresses `lst`, reads the bit / 2-bit value at `idx`.
4. Aggregates verdicts; prints per-statement report.
5. Exits 0 if any statement is trusted, 1 otherwise.

Within a single invocation, the issuer DID document and the status-list JWT are cached
by URL (one fetch each, regardless of how many statements reference them).

#### Out of scope for this version

- `--allow-expired` — for `verify-trust` the question being asked is "currently
  trusted?", so an expired statement is semantically untrusted by design. Add only if
  a debugging use case emerges.
- A separate `--status-issuer` flag — empirically settled: SWIYU signs the status list
  with the same DID as the trust statement.
- Filtering by statement type. `identity` is hardcoded as the only type.
- Caching across invocations.
- Authentication. All endpoints are public.

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
| Both `--jwt` and `--jwt-file` given    | 1         | `error: --jwt and --jwt-file are mutually exclusive`           |
| Neither `--jwt` nor `--jwt-file` given | 1         | `error: provide one of --jwt or --jwt-file`                    |
| JWT not 3 base64url parts              | 1         | `error: JWT is malformed: <reason>`                            |
| Unsupported `alg` (incl. `none`)       | 1         | `error: unsupported alg '<alg>'; expected EdDSA or ES256`      |
| `alg` and key type disagree            | 1         | `error: alg '<alg>' does not match key type <key-type>`        |
| Signature verification failed          | 1         | `error: signature verification failed`                         |
| `iss` disagrees with expected DID      | 1         | `error: payload.iss '<iss>' does not match expected '<did>'`   |
| `did:key` multikey not in `parameters.updateKeys` | 1 | `error: did:key multikey is not present in the latest entry's parameters.updateKeys of '<did>'` |
| `business-entity lookup`: no statements (registry returned `[]` or `404`) | 1 | (none — empty stdout, message on stderr) |
| `business-entity lookup`: `--trust-registry-url` and `SWIYU_TRUST_REGISTRY_URL` both unset | 2 | `error: --trust-registry-url or SWIYU_TRUST_REGISTRY_URL is required` |
| `business-entity lookup`: trust registry HTTPS fetch failed | 2 | `error: cannot fetch '<url>': <reason>` |
| `business-entity lookup`: trust registry returned non-`2xx`, non-`404` | 2 | `error: '<url>' returned <status>: <body>` |
| `business-entity lookup`: response is not a JSON array of strings | 2 | `error: trust registry response is not a JSON array of JWT strings` |
| `business-entity lookup`: trust statement is malformed | 2 | `error: trust statement #<n> is malformed: <reason>` |
| `business-entity verify-trust`: `--trust-issuer` and `SWIYU_TRUST_ISSUER_DID` both unset | 2 | `error: --trust-issuer or SWIYU_TRUST_ISSUER_DID is required` |
| `business-entity verify-trust`: cannot resolve issuer DID log | 2 | `error: cannot resolve issuer DID log: <reason>` |
| `business-entity verify-trust`: status-list HTTPS fetch failed | 2 | `error: cannot fetch status list '<url>': <reason>` |
| `business-entity verify-trust`: status-list JWT malformed | 2 | `error: status list at '<url>' is malformed: <reason>` |
| `business-entity verify-trust`: status-list signature invalid | 2 | `error: status list signature verification failed` |
| `business-entity verify-trust`: status-list bitstring decompression failed | 2 | `error: status list at '<url>' bitstring decompression failed: <reason>` |
| `business-entity verify-trust`: `idx` out of range in bitstring | 2 | `error: status list idx <n> exceeds bitstring length` |
| `business-entity verify-trust`: zero trusted statements | 1 | (none — verdict line on stdout) |
| JWT expired                            | 1         | `error: JWT expired at <iso8601> (<delta> ago)`                |
| `iat` further than 60s in the future   | 1         | `error: JWT has iat in the future (<delta> ahead)`             |
| `--nonce` mismatch                     | 1         | `error: payload.nonce '<actual>' does not match expected '<expected>'` |
| Verification method id missing in DID document | 1 | `error: no verification method with id '<kid>' in DID document` |
| DID derived from kid disagrees with `--did`/`--input` | 1 | `error: DID '<source>' does not match kid's DID '<kid-did>'` |
| `did:key` multikey decoding failed     | 1         | `error: cannot decode did:key multikey: <reason>`              |

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
