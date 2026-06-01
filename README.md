# swiyu-rs

Rust tooling and libraries for [SWIYU](https://www.eid.admin.ch/) — the Swiss eID
infrastructure built on `did:tdw` / `did:webvh` decentralized identifiers.

## Workspace crates

- **[`swiyu-didtool`](./swiyu-didtool/README.md)** — command-line tool to create,
  update, deactivate, and inspect DIDs against the SWIYU Identifier Registry.
  Manages a local key store with the generated DIDs and their key pairs.

- **`swiyu-core`** — library with the underlying primitives: DID parsing,
  DID-log entries, SCID + entryHash derivation, JsonWebKey types, and
  Data Integrity Proof signing.

- **[`swiyu-registries`](./swiyu-registries/README.md)** — clients and types for
  the SWIYU Identifier and Trust registries.

## Status

Work in progress. APIs are not yet stable.

### Supported DID methods

| Method          | Local create | Verified against SWIYU registry |
|-----------------|--------------|---------------------------------|
| `did:tdw` 0.3   | yes          | yes (integration environment)   |
| `did:webvh` 1.0 | yes          | **no test backend available**   |

`did:webvh` 1.0 code paths exist but are not validated end-to-end. There is
currently no registry endpoint we can target for `did:webvh`, so changes to
those paths should be treated as unverified until a test backend becomes
available.

## See also

- **[swiyu-issuer](https://github.com/Gubaer/swiyu-issuer)** — credential issuer
  service for SWIYU (OAuth2 token lifecycle, credential issuance, status list
  management) plus its web frontend. It consumes `swiyu-core` and
  `swiyu-registries` from this workspace and lives in its own repository.

## Contributing

Issues and pull requests welcome.

## License

Licensed under the [MIT License](./LICENSE).

## Acknowledgments

[didtoolbox-java][swiyu-did-toolbox] is the reference implementation of the
SWIYU DID Toolbox and informed the design of this project; protocol behavior
was cross-checked against it during development.

[swiyu-did-toolbox]: https://github.com/swiyu-admin-ch/didtoolbox-java
