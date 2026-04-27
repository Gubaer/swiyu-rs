# didtool CLI

`didtool` is a command-line tool for managing `did:webvh` identities. It handles key generation,
DID creation and updates, and key store access.

# Configuration

## Keystore path

All subcommands that access the key store accept a global `--keystore <path>` flag. If omitted,
the value of the environment variable `DIDTOOL_KEYSTORE` is used. If that is also unset, the
default path `~/.didtool/keys` is used.

```
didtool --keystore /path/to/keys keystore list
```

Priority: `--keystore` flag > `DIDTOOL_KEYSTORE` env var > default.

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

# Output conventions

- Normal output (key material, lists) goes to **stdout**.
- Error messages go to **stderr**.
- The process exits with code `0` on success, non-zero on failure.
- PEM is the only key output format.

# Error handling

Errors are reported as a single human-readable message on stderr followed by a non-zero exit
code. No stack traces or internal details are shown to the user.

| Condition                              | Exit code | Message                                      |
|----------------------------------------|-----------|----------------------------------------------|
| Entry not found in key store           | 1         | `error: no entry found for '<hash|did>'`     |
| Ambiguous hash prefix (future)         | 1         | `error: ambiguous hash '<hash>'`             |
| Key store directory not accessible     | 1         | `error: cannot open key store: <io error>`   |
| Home directory not found               | 1         | `error: cannot resolve home directory`       |
| I/O error writing export file          | 1         | `error: cannot write '<file>': <io error>`   |

# Logging

No logging framework is used. Diagnostic output (e.g. which directory a key was loaded from)
may be added behind a `--verbose` flag in a future version if a concrete need arises.
