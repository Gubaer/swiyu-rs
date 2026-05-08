# Lessons Learned

## Build and test workflow

- Do not run `cargo build` or `cargo test` from the assistant. Ask the user to run them and report results back.
- Do run `cargo fmt`, `cargo fmt --check`, and `cargo clippy -- -D warnings` from the assistant after code changes, and fix anything they flag before handing off.

## Doc Comments

- When referring to a field name or identifier in a doc comment, use a bare backtick identifier: `` `kid` ``, not `` `"kid"` ``.

## Spec file references in comments

- Do not reference `specs/` files (e.g. `specs/impl-issuer.md`) in source comments. The spec is not part of the repo's public surface and the reference rots. Say what the code does; omit the pointer to where the design came from.

## Markdown line wrapping

- In Markdown spec files, do not hard-wrap prose paragraphs. Each paragraph is one long line; the editor or renderer handles soft-wrap. Tables, code blocks, and headings stay on their own lines as Markdown requires; list items each occupy one logical line (continuation text on the same line, not indented onto the next).

## sqlx migration naming

- In `swiyu-issuer/migrations/`, files use the convention `<DATE>_<SEQ>_<description>.sql` (e.g. `20260507_000003_issued_credentials.sql`). sqlx parses **only the leading numeric run before the first underscore** as the migration version — the `_000003` sequence number is part of the description, not the version. Two files with the same date prefix collide on `_sqlx_migrations.version` and fail at apply time with a `23505` duplicate-key error inside every `sqlx::test`. When adding a migration, pick a date prefix no existing migration uses. The sequence number is human-ordering only.
