# swiyu-rs

Rust tooling and libraries for [SWIYU](https://www.eid.admin.ch/) — the Swiss eID
infrastructure built on `did:tdw` / `did:webvh` decentralized identifiers.

The workspace contains two crates:

- **`swiyu-didtool`** — a command-line tool to create, update, deactivate, and
  inspect DIDs against the SWIYU Identifier Registry. Manages a local key
  store with the generated DIDs and their key pairs.

- **`swiyu-core`** — a library with the underlying primitives: DID parsing,
  DID-log entries, SCID + entryHash derivation, JsonWebKey types, and
  Data Integrity Proof signing.

## Learn by example

If you like specific real-world examples, walk through the
[sample use case](./swiyu-didtool/doc/sample-use-case.md): a small Swiss consulting
company onboards as a SWIYU issuer, registers a DID against the Identifier Registry,
gets a Trust Statement issued for it, rotates its keys, and finally deactivates it.
Every command is shown together with its real output, so you can follow along verbatim
against the SWIYU integration environment or adapt the steps to your own organisation.

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

### Using `didtool`

Create a DID, rotate a key, deactivate:

```sh
# Allocate a DID space, sign the genesis log entry, publish to the registry.
didtool did create

# Append a new entry that rotates the authentication key; publish.
didtool did rotate --did did:tdw:Qmb7D2murY... --role authentication

# Append a final entry marking the DID as deactivated; publish.
didtool did deactivate --did did:tdw:Qmb7D2murY...
```

Inspect a DID's log:

```sh
# Local file or fetched over HTTPS via --did <did-or-keystore-hash>.
didtool didlog list --did did:tdw:Qmb7D2murY...
# or:
didtool didlog show --did did:tdw:Qmb7D2murY... --pretty
didtool didlog entry --did did:tdw:Qmb7D2murY... --at latest
```

Manage the local key store:

```sh
didtool key list
didtool key versions --did did:tdw:Qmb7D2murY...
didtool key show --did did:tdw:Qmb7D2murY...
didtool key export --did did:tdw:Qmb7D2murY... --role authorized --out key.pem
```

> [!CAUTION]
> The `didtool` keystore writes private keys to disk **unencrypted** (PEM files
> in the keystore directory). This is fine for development against the SWIYU
> integration environment, but **do not use `didtool` for production keys**.

Produce a Proof of Possession (PoP) — a JWT signed with one of a DID's keys.
Useful for registry onboarding handshakes and low-level testing:

```sh
# Sign with the assertion key; auto-generate a nonce (printed to stderr).
didtool pop create --did did:tdw:Qmb7D2murY... > pop.jwt

# Sign with the authorized key, embed a verifier-supplied challenge, write to a file.
didtool pop create --did did:tdw:Qmb7D2murY... \
    --role authorized --nonce "<challenge>" --out pop.jwt
```

Verify a PoP — checks signature, freshness, and (optionally) the nonce. For a
PoP signed with the authorized key, also verifies the multikey against the
DID's `parameters.updateKeys` when a log source is supplied:

```sh
# Verify a PoP from a string.
didtool pop verify --jwt "$(cat pop.jwt)"

# Verify against a fresh registry fetch, with an expected nonce.
didtool pop verify --jwt-file pop.jwt --did did:tdw:Qmb7D2murY... --nonce "<challenge>"
```

Look up the SWIYU trust granted to a DID — displays the disclosed claims
(entity name per locale, state-actor flag, status list pointer). Display only;
signatures and revocation are not checked. Exit codes are `0` (statements
found), `1` (none found — i.e. *untrusted*), `2` (operational error):

```sh
# With SWIYU_TRUST_REGISTRY_URL set in .env.
didtool trust lookup --did did:tdw:QmPAaz...

# Or via the flag.
didtool trust lookup --did did:tdw:QmPAaz... \
    --trust-registry-url https://trust-reg.trust-infra.swiyu-int.admin.ch
```

Verify that a DID is currently vouched-for by SWIYU — checks the issuer
allowlist, ES256 signature, freshness (`nbf`/`exp`), and revocation via the
issuer-signed status list. Reports a per-statement breakdown plus an overall
verdict. Exit codes are `0` (trusted), `1` (untrusted — no statement passes
all checks), `2` (operational error):

```sh
# With SWIYU_TRUST_REGISTRY_URL and SWIYU_TRUST_ISSUER_DID set in .env.
didtool trust verify --did did:tdw:QmPAaz...

# Or with the flags.
didtool trust verify --did did:tdw:QmPAaz... \
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