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

Build the CLI:

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