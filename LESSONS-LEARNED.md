# Lessons Learned

## Build and test workflow

- Do not run `cargo build`, `cargo test`, or `cargo doc` from the assistant. Ask the user to run them and report results back.
- Do run `cargo fmt`, `cargo fmt --check`, and `cargo clippy -- -D warnings` from the assistant after code changes, and fix anything they flag before handing off.

## Commits

- When the user asks for a commit, always add the assistant as Co-Author (`Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`) in the commit message trailer.

## Doc Comments

- When referring to a field name or identifier in a doc comment, use a bare backtick identifier: `` `kid` ``, not `` `"kid"` ``.
- When a doc comment references another item (method, field, type, variant), use an intra-doc link, not plain backticks. Prefer the shortcut form `` [`name`][Type::name] `` over the full-path form `` [`Type::name`] `` — the visible text stays a bare identifier so the prose reads naturally, while the link still resolves. Reserve full-path link text for the rare case where the type qualification adds disambiguation a reader needs. Verify links with `RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p <crate> --no-deps --document-private-items` after any docs change.
- Don't link every mention. Link the first reference in a paragraph; leave subsequent prose mentions of the same item as plain backticks. State-machine vocabulary (`Pending`, `InProgress`, etc.) used as English nouns in flowing prose stays plain backticks; link only the items a reader would want to navigate to (methods, error variants, cross-module symbols).

## Spec file references in comments

- Do not reference `specs/` files (e.g. `specs/impl-issuer.md`) in source comments. The spec is not part of the repo's public surface and the reference rots. Say what the code does; omit the pointer to where the design came from.

## Markdown line wrapping

- In Markdown spec files, do not hard-wrap prose paragraphs. Each paragraph is one long line; the editor or renderer handles soft-wrap. Tables, code blocks, and headings stay on their own lines as Markdown requires; list items each occupy one logical line (continuation text on the same line, not indented onto the next).
