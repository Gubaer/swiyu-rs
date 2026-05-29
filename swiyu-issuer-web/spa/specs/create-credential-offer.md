# Create Credential Offer in the SPA

## Goal

Let an operator create a credential offer from the SPA: pick an issuer and one of its assigned credential types, edit the offer's `claims` in an embedded JSON editor with syntax highlighting and live schema validation, optionally set a lifetime, submit, and capture the one-time result (pre-auth code + deeplink as a scannable QR).

## Decisions

- **Claims input**: an embedded code editor (not a raw textarea, not a schema-rendered form), with JSON syntax highlighting.
- **Editor library**: Monaco (the VS Code editor engine). Wrap the raw `monaco-editor` package in a thin standalone component rather than depending on an Angular wrapper lib, because first-class wrappers tend to lag the framework version (SPA is on Angular 21). Accept the heavier bundle and the web-worker setup cost in exchange for native JSON-Schema support.
- **Schema validation**: live, client-side. The credential type's `claim_schema` is pushed into Monaco's JSON `diagnosticsOptions` so the operator sees inline errors and autocomplete as they type. The backend remains the authoritative validator on submit; the client-side pass is a UX aid, not a security boundary.
- **Result display**: render the `openid-credential-offer://` deeplink as a scannable QR code, plus copy buttons for the deeplink and the pre-auth code, with a clear "shown once" warning. Needs a small QR library in the SPA.

## Backend contracts (already implemented in the issuer management API)

The issuer management API already supports everything needed; no backend changes are required.

- `POST /api/v1/issuers/{issuer_id}/credential-offers` — `swiyu-issuer/src/api_management/credential_offers.rs`. Request body: `credential_type_id` (bare bs58), `claims` (JSON, validated against the type's compiled JSON Schema), `expires_in_seconds` (optional; default 600, bounded 60–3600). Returns `201` with `id`, `pre_auth_code`, `offer_deeplink`, `expires_at`. The pre-auth code is returned exactly once — only its hash is persisted, so it cannot be re-fetched.
- `GET /api/v1/issuers/{issuer_id}/credential-types` — `list_assignments`. Returns `{ items: [GetCredentialTypeResponse] }`. This is the offer-type picker's option list. Note: this response deliberately omits `claim_schema` (blob columns are served separately to keep list pages small), so it cannot feed Monaco on its own.
- `GET /api/v1/credential-types/{credential_type_id}/schema` — `get_schema`. Returns the raw JSON Schema (`application/schema+json`). This is the source for Monaco's live validation, fetched once the operator picks a type.

## BFF work — 3 new proxy endpoints

Thin pass-throughs in the style of the existing offer read proxies (`swiyu-issuer-web/bff/src/upstream/mgmt_api.rs` + `swiyu-issuer-web/bff/src/routes/`).

1. `POST /api/issuers/{issuer_id}/credential-offers` → mgmt `create`. Returns the 201 body verbatim (pre-auth code + deeplink).
2. `GET /api/issuers/{issuer_id}/credential-types` → `list_assignments`. The type picker's options.
3. `GET /api/credential-types/{credential_type_id}/schema` → `get_schema`. The JSON Schema for Monaco.

## SPA work

- **Monaco integration**: add the `monaco-editor` dependency, wire its web workers into the esbuild-based `@angular/build:application` builder, and wrap it in one small reusable standalone `JsonEditor` component. The component takes the value in/out and a `schema` input it pushes to Monaco's JSON `diagnosticsOptions`. This is the riskiest piece on Angular 21 + esbuild and is a candidate to spike on its own before the rest of the flow.
- **Credential-types read service/store**: backs the type picker and the per-type schema fetch.
- **Create-offer flow**: reuse the existing issuer selection, add a credential-type picker, the Monaco claims editor (seeded from the schema, showing live errors), an optional `expires_in_seconds` input, and submit. Mirror the existing `issuer-create` component pattern (`swiyu-issuer-web/spa/src/app/features/issuers/issuer-create.ts`) for consistency.
- **Result view**: QR of the deeplink + copyable deeplink and pre-auth code, with an unmissable "shown once" warning, since the values cannot be re-fetched.
- **Entry point + routing**: a "New offer" action on the credential-offers list page.

## Open items

- **Sequencing**: whether to ship in one pass or stage it (BFF proxies first so the API is independently testable, then the Monaco `JsonEditor` spike, then the full create flow and result screen).
- **QR library choice** for the SPA.
- **Next step** for the assistant (detailed implementation plan vs. start building) was left undecided at the end of the discussion.
