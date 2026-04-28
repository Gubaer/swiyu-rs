# swiyu-rs

A Rust workspace for working with [SWIYU](https://www.swiyu.admin.ch/) DIDs.

- `swiyu-core` — DID document, DID log, SCID, and cryptography primitives.
- `swiyu-didtool` — CLI for creating and managing DID logs and key material.

## Status

Work in progress.

### Supported DID methods

| Method          | Local create | Verified against SWIYU registry |
|-----------------|--------------|---------------------------------|
| `did:tdw` 0.3   | yes          | yes (integration environment)   |
| `did:webvh` 1.0 | yes          | **no test backend available**   |

`did:webvh` 1.0 code paths exist but are not validated end-to-end. There is
currently no registry endpoint we can target for `did:webvh`, so changes to
those paths should be treated as unverified until a test backend becomes
available.
