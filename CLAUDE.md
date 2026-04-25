# CLAUDE.md

Always read `LESSONS-LEARNED.md` at the start of every session and follow the guidance it contains.

## Language and Edition

- Rust, edition 2024
- Target: stable toolchain

## Core Philosophy

Write code for human readers first. A future engineer should be able to understand any piece of code without needing to know Rust deeply or hold the whole system in their head. When in doubt, choose the obvious solution over the clever one.

## Code Style

**Prefer simple and boring constructs.**

- Use plain `if`/`else` and `match` rather than combinator chains when it aids clarity.
- Use `for` loops when iteration logic is non-trivial; reach for `map`/`filter`/`collect` only when they read more naturally than the loop equivalent.
- Keep functions short and focused. If a function needs a comment to explain what it does, consider splitting it.
- Avoid deeply nested closures, complex iterator chains, or type-level tricks unless there is a concrete benefit.

**Name things clearly.**

- Use full, descriptive names. `connection_timeout` beats `conn_tmo`.
- Match the vocabulary of the domain; if the spec says "credential", use `credential`, not `cred`.
- Avoid single-letter names outside of trivial loop indices.

**Error handling.**

- Define explicit error types (e.g., via `thiserror`) rather than boxing everything as `Box<dyn Error>`.
- Use `?` propagation; avoid `.unwrap()` and `.expect()` except in tests or cases where the invariant is provably unbreakable and you leave a short comment explaining why.
- Surface meaningful context in error messages.

**Ownership and borrowing.**

- Prefer returning owned values over handing out references when lifetime complexity would otherwise creep in.
- Avoid lifetime annotations in public APIs unless unavoidable.
- Use `Arc`/`Mutex` only when shared mutable state is genuinely required; prefer message passing or function arguments instead.

**Traits and generics.**

- Only introduce a trait when there are (or will imminently be) multiple implementors.
- Keep generic bounds minimal. If a function works with a concrete type, use the concrete type.
- Avoid blanket implementations that are hard to reason about.

**Async.**

- Use `async`/`await` (tokio runtime) only where I/O concurrency is needed.
- Keep async fn bodies focused; extract CPU-bound or complex logic into plain sync functions called from within the async fn.

## Comments

Write comments only when the *why* is not obvious from the code itself. Do not restate what the code does. Do not write module-level or function-level doc comments unless the item is part of a public API intended for external consumers.

## Testing

- Write unit tests in a `#[cfg(test)]` module inside the same file as the code under test.
- Test behavior, not implementation details.
- Prefer straightforward assertions over elaborate test helpers unless the helpers genuinely reduce duplication.
- Use integration tests in `tests/` for end-to-end behavior across module boundaries.

## Dependencies

- Add a dependency only when it solves a real problem that is not trivially solved in a few lines.
- Prefer well-maintained crates from the ecosystem (e.g., `tokio`, `serde`, `thiserror`, `clap`, `tracing`) over rolling bespoke solutions for common problems.
- Keep `Cargo.toml` tidy: remove unused dependencies promptly.

## Formatting and Lints

- All code must pass `cargo fmt` and `cargo clippy -- -D warnings` without modification.
- After every code change, run `cargo fmt --check && cargo clippy -- -D warnings` before reporting work as done. Never skip this, not even for small edits.
- Do not suppress clippy lints with `#[allow(...)]` without a comment explaining the reason.
