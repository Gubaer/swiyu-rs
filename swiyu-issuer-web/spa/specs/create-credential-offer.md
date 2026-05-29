# Create Credential Offer in the SPA

## Goal

Let an operator create a credential offer from the SPA: pick an issuer and one of its assigned credential types, edit the offer's `claims` in an embedded JSON editor with syntax highlighting and live schema validation, optionally set a lifetime, submit, and capture the one-time result (pre-auth code + deeplink as a scannable QR).

## Decisions

- **Flow shape**: a linear wizard (see UX flow below) rather than a single dense form, because the choices are genuinely sequential — the credential-type list is fetched per issuer and the JSON Schema that drives the editor is fetched per type.
- **Wizard presentation**: full-page routed steps (`/credential-offers/new/...`), not a modal/overlay stepper. Monaco wants vertical room and the terminal result page is awkward to host inside a modal.
- **Claims input**: an embedded code editor (not a raw textarea, not a schema-rendered form), with JSON syntax highlighting.
- **Editor library**: Monaco (the VS Code editor engine). Wrap the raw `monaco-editor` package in a thin standalone component rather than depending on an Angular wrapper lib, because first-class wrappers tend to lag the framework version (SPA is on Angular 21). Accept the heavier bundle and the web-worker setup cost in exchange for native JSON-Schema support.
- **Schema validation**: live, client-side. The credential type's `claim_schema` is pushed into Monaco's JSON `diagnosticsOptions` so the operator sees inline errors and autocomplete as they type. The backend remains the authoritative validator on submit; the client-side pass is a UX aid, not a security boundary.
- **Initial claims**: the editor opens on a best-effort skeleton generated from the selected type's JSON Schema rather than an empty buffer. Generation handles the common case (objects, scalar properties, `enum` and `required` hints) and falls back to `{}` for constructs it cannot resolve (`$ref`, `oneOf`/`anyOf`, deeply nested combinators). Scalar placeholders use obvious sentinels (e.g. `"REPLACE_ME"`) that are schema-valid but visibly fake, so the editor starts green while signalling that every value must be replaced before the offer is real. The backend validates schema-conformance, not semantics, so a skeleton submitted unchanged would mint a real offer full of placeholder claims — the visible sentinels are the guard against that.
- **Result display**: render the `openid-credential-offer://` deeplink as a scannable QR code, plus copy buttons for the deeplink and the pre-auth code, with a clear "shown once" warning.
- **QR library**: the framework-agnostic `qrcode` (node-qrcode) package, wrapped in a thin standalone `QrCode` component that outputs SVG (crisp at any size, styleable, printable). Same wrapper principle as the Monaco decision: depend on the raw library, not an Angular wrapper lib that would lag the framework version.

## UX flow

A linear three-step wizard. The steps are sequential because each choice narrows the next.

1. **Choose issuer and credential type** — a single step with two dependent selects. The issuer picker reuses the existing issuer selection. The credential-type picker is disabled until an issuer is chosen and (re)populates from `GET /api/issuers/{issuer_id}/credential-types` whenever the selected issuer changes.
2. **Edit the offer** — the Monaco claims editor seeded with the schema-derived skeleton, live-validated against the type's `claim_schema`, plus an optional "expires in" field defaulting to 600 seconds (bounded 60–3600). Submit lives on this step.
3. **Result** — a terminal page showing the structured offer attributes (including the one-time pre-authorization code), the `openid-credential-offer://` deeplink as a scannable QR, and copy buttons, under an unmissable "shown once" warning. Because the pre-auth code cannot be re-fetched, this step does not allow back-navigation that would lose it; it offers only "Create another" (restart at step 1) and a close/return-to-list action.

The earlier sketch split issuer selection and type selection into separate steps. They are merged here because each is a single dropdown and the type list depends on the chosen issuer, so showing both on one screen keeps that relationship visible and saves a click on a flow operators will repeat.

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
- **Skeleton generator**: a small pure function that turns a JSON Schema into a best-effort schema-valid scaffold with sentinel placeholders, falling back to `{}` on constructs it cannot handle. Unit-test it directly against representative `claim_schema` shapes.
- **Create-offer flow**: a three-step wizard (see UX flow). Step 1 combines the issuer select (reusing the existing issuer selection) with a dependent credential-type picker. Step 2 hosts the Monaco claims editor seeded from the skeleton, showing live errors, and the optional `expires_in_seconds` input. Mirror the existing `issuer-create` component pattern (`swiyu-issuer-web/spa/src/app/features/issuers/issuer-create.ts`) for consistency.
- **QR component**: a thin standalone `QrCode` wrapper over the `qrcode` package, rendering SVG; takes the value in, emits no events.
- **Result view**: the terminal step 3 — QR of the deeplink + copyable deeplink and pre-auth code, with an unmissable "shown once" warning, since the values cannot be re-fetched.
- **Entry point + routing**: a "New offer" action on the credential-offers list page.

## Sequencing

Staged, not one pass. The stages build on each other and each is independently verifiable:

1. **BFF proxies** first, so the new API surface is testable on its own before any SPA work depends on it.
2. **Monaco `JsonEditor` spike** next — the riskiest piece on Angular 21 + esbuild (dependency, web-worker wiring, schema diagnostics). De-risk it in isolation before building the flow around it.
3. **Full create flow and result screen** last, once the editor and the proxies are known-good.

See `plan-create-credential-offer.md` for the detailed step-by-step plan.

## Open items

_None — all decisions resolved; see Sequencing above and `plan-create-credential-offer.md`._
