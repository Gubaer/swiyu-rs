# Lessons Learned

## Doc Comments

- When referring to a field name or identifier in a doc comment, use a bare backtick identifier: `` `kid` ``, not `` `"kid"` ``.

## Markdown line wrapping

- In Markdown spec files, do not hard-wrap prose paragraphs. Each paragraph is one long line; the editor or renderer handles soft-wrap. Tables, code blocks, and headings stay on their own lines as Markdown requires; list items each occupy one logical line (continuation text on the same line, not indented onto the next).
