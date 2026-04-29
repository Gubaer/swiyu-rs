# swiyu-rs

Rust tooling and libraries for [SWIYU](https://www.swiyu.admin.ch/) — the Swiss eID
infrastructure built on `did:tdw` / `did:webvh` decentralized identifiers.

The workspace contains two crates:

- **`swiyu-didtool`** — a command-line tool to create, update, deactivate, and
  inspect DIDs against the SWIYU Identifier Registry. Manages a local key
  store with the generated DIDs and their key pairs.

- **`swiyu-core`** — a library with the underlying primitives: DID parsing,
  DID-log entries, SCID + entryHash derivation, JsonWebKey types, and
  Data Integrity Proof signing.

## Status

Work in progress. The `didtool` CLI is usable end-to-end against the SWIYU integration environment; APIs are not yet stable.

### Supported DID methods

| Method          | Local create | Verified against SWIYU registry |
|-----------------|--------------|---------------------------------|
| `did:tdw` 0.3   | yes          | yes (integration environment)   |
| `did:webvh` 1.0 | yes          | **no test backend available**   |

`did:webvh` 1.0 code paths exist but are not validated end-to-end. There is
currently no registry endpoint we can target for `did:webvh`, so changes to
those paths should be treated as unverified until a test backend becomes
available.

## Quick start

### Build from source

```sh
# clone the repo
git clone <repo-url>
cd swiyu-rs

# build the didtool CLI
cargo build --release

# put didtool on PATH for the rest of this shell
export PATH="$(pwd)/target/release:$PATH"

# run didtool
didtool --help
```

### Or use the Docker image

The `didtool` CLI is also published as a container image targeting the SWIYU
Beta infrastructure:

```sh
docker pull ghcr.io/gubaer/didtool:swiyu-beta
```

Available tags:

- `swiyu-beta` — floating tag, follows the latest published build.
- `<version>-swiyu-beta` (e.g. `0.1.4-swiyu-beta`) — pinned to a specific release.

The image bakes in the SWIYU Beta registry URLs, so users only need to supply
`SWIYU_PARTNER_ID` and `SWIYU_ACCESS_TOKEN`. The key store persists in the named
Docker volume `didtool-keys`; reset it with `docker volume rm didtool-keys`.

Drop this shell function into `~/.bashrc` / `~/.zshrc` so the rest of the
examples below work the same as a native install:

```sh
didtool() {
    docker run --rm -it \
        -v didtool-keys:/data \
        -e SWIYU_PARTNER_ID -e SWIYU_ACCESS_TOKEN \
        -e SWIYU_IDENTIFIER_REGISTRY_URL \
        -e SWIYU_TRUST_REGISTRY_URL \
        -e SWIYU_TRUST_ISSUER_DID \
        ghcr.io/gubaer/didtool:swiyu-beta "$@"
}
```

PowerShell equivalent for `$PROFILE`:

```powershell
function didtool {
    docker run --rm -it `
        -v didtool-keys:/data `
        -e SWIYU_PARTNER_ID -e SWIYU_ACCESS_TOKEN `
        -e SWIYU_IDENTIFIER_REGISTRY_URL `
        -e SWIYU_TRUST_REGISTRY_URL `
        -e SWIYU_TRUST_ISSUER_DID `
        ghcr.io/gubaer/didtool:swiyu-beta @args
}
```

`-it` keeps interactive use feeling native but trips up scripted/CI contexts —
drop the `-t` (or call `docker run` directly) when there's no terminal attached.

### Configure credentials

Set the SWIYU credentials (or load them via [direnv](https://direnv.net/) from
a local `.env`). See [`.env.example`](./.env.example) for a template `.env` file.

Create a DID, rotate a key, deactivate:

```sh
# Allocate a DID space, sign the genesis log entry, publish to the registry.
didtool create --swiyu --format tdw

# Append a new entry that rotates the authentication key; publish.
didtool update --rotate authentication

# Append a final entry marking the DID as deactivated; publish.
didtool deactivate
```

Inspect a DID's log:

```sh
# Local file or fetched over HTTPS via --did <did-or-keystore-hash>.
didtool log list --did did:tdw:Qmb7D2murY...
# or:
didtool log show --did did:tdw:Qmb7D2murY... --pretty
didtool log entry --did did:tdw:Qmb7D2murY... --at latest
```

Manage the local key store:

```sh
didtool keystore list
didtool keystore show --did did:tdw:Qmb7D2murY...
didtool keystore export --did did:tdw:Qmb7D2murY... --role authorized --out key.pem
```

Produce a Proof of Possession (PoP) — a JWT signed with one of a DID's keys.
Useful for registry onboarding handshakes and low-level testing:

```sh
# Sign with the assertion key; auto-generate a nonce (printed to stderr).
didtool create-pop --did did:tdw:Qmb7D2murY... > pop.jwt

# Sign with the authorized key, embed a verifier-supplied challenge, write to a file.
didtool create-pop --did did:tdw:Qmb7D2murY... \
    --role authorized --nonce "<challenge>" --out pop.jwt
```

Verify a PoP — checks signature, freshness, and (optionally) the nonce. For a
PoP signed with the authorized key, also verifies the multikey against the
DID's `parameters.updateKeys` when a log source is supplied:

```sh
# Verify a PoP from a string.
didtool verify-pop --jwt "$(cat pop.jwt)"

# Verify against a fresh registry fetch, with an expected nonce.
didtool verify-pop --jwt-file pop.jwt --did did:tdw:Qmb7D2murY... --nonce "<challenge>"
```

Look up the SWIYU trust registry's statements about a business entity DID —
displays the disclosed claims (entity name per locale, state-actor flag, status
list pointer). Display only; signatures and revocation are not checked. Exit
codes are `0` (statements found), `1` (none found — i.e. *untrusted*), `2`
(operational error):

```sh
# With SWIYU_TRUST_REGISTRY_URL set in .env.
didtool business-entity lookup --did did:tdw:QmPAaz...

# Or via the flag.
didtool business-entity lookup --did did:tdw:QmPAaz... \
    --trust-registry-url https://trust-reg.trust-infra.swiyu-int.admin.ch
```

Verify that a business entity is currently vouched-for by SWIYU — checks the
issuer allowlist, ES256 signature, freshness (`nbf`/`exp`), and revocation via
the issuer-signed status list. Reports a per-statement breakdown plus an
overall verdict. Exit codes are `0` (trusted), `1` (untrusted — no statement
passes all checks), `2` (operational error):

```sh
# With SWIYU_TRUST_REGISTRY_URL and SWIYU_TRUST_ISSUER_DID set in .env.
didtool business-entity verify-trust --did did:tdw:QmPAaz...

# Or with the flags.
didtool business-entity verify-trust --did did:tdw:QmPAaz... \
    --trust-registry-url https://trust-reg.trust-infra.swiyu-int.admin.ch \
    --trust-issuer did:tdw:QmWrXW...:2e246676-...
```

## Configuration

See [`.env.example`](./.env.example).

## Contributing

Issues and pull requests welcome.

## License

Licensed under the [MIT License](./LICENSE).

## Acknowledgments

[didtoolbox-java][swiyu-did-toolbox] is the reference implementation of the
SWIYU DID Toolbox and informed the design of this project; protocol behavior
was cross-checked against it during development.

[swiyu-did-toolbox]: https://github.com/swiyu-admin-ch/didtoolbox-java