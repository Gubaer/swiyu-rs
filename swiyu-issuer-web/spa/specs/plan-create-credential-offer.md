# Implementation Plan: Create Credential Offer in the SPA

Detailed, staged plan for `create-credential-offer.md`. Three stages, each independently verifiable: BFF proxies first, then the Monaco editor spike, then the full create flow and result screen. Build later stages only once the earlier one is verified.

All decisions are settled in the spec: three-step wizard, full-page routed steps under `/credential-offers/new/...`, Monaco wrapped in a thin standalone component, schema-derived skeleton with `"REPLACE_ME"` sentinels, `qrcode` (node-qrcode) wrapped as an SVG `QrCode` component.

## Conventions to follow

- **Rust (BFF)**: after every edit run `cargo fmt --check && cargo clippy -- -D warnings` from the BFF crate and fix anything flagged. Do **not** run `cargo build`/`cargo test`/`cargo doc` — ask the operator to run those and report back.
- **SPA**: mirror existing feature conventions — standalone components with explicit `imports`, signal-based stores (`@Injectable({ providedIn: 'root' })`, `.asReadonly()` public views), `FormBuilder.nonNullable.group()` reactive forms, lazy routes via `loadComponent`, Transloco for all user-facing strings, relative `/api` base URL. Run `npx prettier --write` on touched files. The operator runs `ng build` / `ng test` (vitest) to verify.

---

## Stage 1 — BFF proxy endpoints

Three thin pass-throughs in the existing style. The mgmt API already implements the upstream routes; the BFF just forwards.

### 1.1 Upstream client — `swiyu-issuer-web/bff/src/upstream/mgmt_api.rs`

Add three methods next to `list_credential_offers` / `get_credential_offer`, following the same shape (build URL from `self.base_url`, send via `self.http`, funnel through `read_json`):

- `create_credential_offer(&self, issuer_id: &str, body: Value) -> Result<Value, CallError>` → `POST {base}/api/v1/issuers/{issuer_id}/credential-offers`, `.json(&body)`.
- `list_credential_types(&self, issuer_id: &str) -> Result<Value, CallError>` → `GET {base}/api/v1/issuers/{issuer_id}/credential-types`.
- `get_credential_type_schema(&self, credential_type_id: &str) -> Result<Value, CallError>` → `GET {base}/api/v1/credential-types/{credential_type_id}/schema`.

Note on the schema endpoint: upstream returns `application/schema+json`. `read_json` deserializes to `serde_json::Value` regardless of content-type, so a JSON Schema body comes through fine. The BFF will re-serialize it as `application/json` — acceptable, since Monaco only needs the parsed schema object, not the exact media type.

### 1.2 Route handlers — `swiyu-issuer-web/bff/src/routes/credential_offers.rs` (+ a new `credential_types.rs`)

In `credential_offers.rs`, add:

```rust
pub async fn create_credential_offer(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let payload = state.mgmt_api.create_credential_offer(&issuer_id, body).await?;
    Ok((StatusCode::CREATED, Json(payload)))
}
```

The create response carries the one-time pre-auth code and deeplink — forward it **verbatim**, do not strip anything (contrast with `list_credential_offers`, which calls `strip_claims_from_items`).

New file `swiyu-issuer-web/bff/src/routes/credential_types.rs` for the two credential-type handlers (keeps the offers file focused; matches the one-file-per-resource layout of `issuers.rs` / `me.rs`):

```rust
pub async fn list_credential_types(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.list_credential_types(&issuer_id).await?;
    Ok(Json(payload))
}

pub async fn get_credential_type_schema(
    State(state): State<AppState>,
    Path(credential_type_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.get_credential_type_schema(&credential_type_id).await?;
    Ok(Json(payload))
}
```

Declare `mod credential_types;` in `swiyu-issuer-web/bff/src/routes/mod.rs`.

### 1.3 Router registration — `swiyu-issuer-web/bff/src/routes/mod.rs`

Extend the existing offers route with `.post(...)` and add the two type routes:

```rust
.route(
    "/api/issuers/{issuer_id}/credential-offers",
    get(credential_offers::list_credential_offers)
        .post(credential_offers::create_credential_offer),
)
.route(
    "/api/issuers/{issuer_id}/credential-types",
    get(credential_types::list_credential_types),
)
.route(
    "/api/credential-types/{credential_type_id}/schema",
    get(credential_types::get_credential_type_schema),
)
```

### 1.4 Tests

The existing BFF tests are unit-level on pure transforms (e.g. `strip_claims_from_items`). These three handlers have no transform logic — they forward verbatim — so there is little pure logic to unit-test. Add a unit test only if a transform is introduced. Otherwise rely on manual verification (below).

### 1.5 Verify Stage 1 (operator)

- `cargo fmt --check && cargo clippy -- -D warnings` (assistant runs).
- Operator runs the BFF against the mgmt API and exercises:
  - `GET /api/issuers/{id}/credential-types` returns `{ items: [...] }`.
  - `GET /api/credential-types/{type_id}/schema` returns a JSON Schema object.
  - `POST /api/issuers/{id}/credential-offers` with `{ credential_type_id, claims, expires_in_seconds? }` returns `201` with `id`, `pre_auth_code`, `offer_deeplink`, `expires_at`.

---

## Stage 2 — Monaco `JsonEditor` spike

The riskiest piece on Angular 21 + the esbuild `@angular/build:application` builder. Build and verify it in isolation before wiring it into the flow.

### 2.1 Dependency

`monaco-editor` added to `swiyu-issuer-web/spa/package.json` (resolved to 0.55.1).

### 2.2 Worker wiring — ESM `getWorker` (the approach the spike landed on)

The spike resolved this. The AMD/assets approach originally planned here does **not** fit monaco 0.55: its `min/vs` distribution moved workers to content-hashed bundles and dropped the classic `base/worker/workerMain.js`, so the old `getWorkerUrl` → `workerMain.js` proxy is dead. monaco 0.55 instead ships canonical ESM worker entry points and supports `MonacoEnvironment.getWorker`, which the esbuild `@angular/build:application` builder bundles natively. So we import the ESM build and let esbuild bundle the workers — no asset copying, no AMD loader.

What was implemented (all under `swiyu-issuer-web/spa/src/app/shared/json-editor/`):

- Two one-line worker shims that esbuild turns into separate worker bundles:
  - `editor.worker.ts` → `import 'monaco-editor/esm/vs/editor/editor.worker.js';`
  - `json.worker.ts` → `import 'monaco-editor/esm/vs/language/json/json.worker.js';`
- In `json-editor.ts`, set the global before any editor is created:
  ```ts
  (globalThis as ...).MonacoEnvironment = {
    getWorker(_id, label) {
      const url = label === 'json' ? new URL('./json.worker', import.meta.url)
                                   : new URL('./editor.worker', import.meta.url);
      return new Worker(url, { type: 'module' });
    },
  };
  ```
- Import only the editor API plus the JSON language, not the full barrel, to keep the chunk lean: `import * as monaco from 'monaco-editor/esm/vs/editor/editor.api.js';` and `import { jsonDefaults } from 'monaco-editor/esm/vs/language/json/monaco.contribution.js';`. Deep ESM paths need the explicit `.js` (the package `exports` map maps `./*` → `./*`).

Two builder/typing wrinkles the spike fixed:

- **Codicon font**: Monaco's CSS pulls a `.ttf`. The builder errors with "No loader is configured for .ttf". Fixed by adding `"loader": { ".ttf": "file" }` to the build `options` in `angular.json`.
- **`jsonDefaults` typing**: in 0.55 the runtime module exports `{ getWorker, jsonDefaults }`, but its per-module `.d.ts` is `export {}` (types only live in the full barrel `.d.ts`). A small local ambient declaration `monaco-json.d.ts` types just the `jsonDefaults.setDiagnosticsOptions` slice we use. (The old `monaco.languages.json.jsonDefaults` accessor is deprecated in 0.55.)

### 2.3 `JsonEditor` component — `swiyu-issuer-web/spa/src/app/shared/json-editor/json-editor.ts`

Implemented as a thin standalone wrapper:

- Signal inputs `value` (string) and `schema` (JSON Schema object or `null`); outputs `valueChange` (string) and `validChange` (boolean, derived from Monaco error markers so the wizard can gate Submit).
- Creates a single model on a fixed in-memory URI; pushes the schema into `jsonDefaults.setDiagnosticsOptions({ validate: true, schemas: [{ uri, fileMatch: [uri], schema }] })`; an `effect` re-applies the schema when it changes and another syncs external `value` changes into the model without clobbering the cursor.
- Validity computed from `monaco.editor.getModelMarkers` on `onDidChangeMarkers`; editor/model/listeners disposed in `ngOnDestroy`.

Generic — no credential-offer specifics.

### 2.4 Verify Stage 2

Build-time gate (done): `ng build` succeeds; both `editor-worker` and `json-worker` chunks are emitted; Monaco lands in lazy chunks (it added ~1.8 kB to the initial bundle). Note: the build prints a pre-existing initial-bundle budget *warning* (~874 kB baseline vs the 500 kB budget, from PrimeNG + Angular) — it predates this work and is a warning, not an error.

Runtime gate (operator, needs a browser): a temporary spike host at route `spike/json-editor` (`json-editor-spike.ts`) mounts `JsonEditor` with a demo schema. Confirm JSON highlighting renders, editing emits `valueChange`, an invalid value shows inline red squiggles and flips `validChange` to false, and the workers spawn (no console errors). **Remove the spike host and its route in Stage 3.**

---

## Stage 3 — Create-offer flow and result screen

Built once Stages 1 and 2 are green. New feature files under `swiyu-issuer-web/spa/src/app/features/credential-offers/`.

### 3.1 Credential-types read service + store

- `credential-types-service.ts`: `HttpClient` calls to `/api/issuers/{issuerId}/credential-types` (list) and `/api/credential-types/{typeId}/schema` (schema). Define response types: `CredentialTypeSummary` (from the assignment list) and the schema as an opaque JSON object.
- `credential-types-store.ts`: signal-based, mirrors `credential-offers-store.ts`. Holds the per-issuer type list and the currently-fetched schema. Apply the same stale-response guard pattern (tag in-flight requests with the intended issuer/type id and drop mismatched responses).

### 3.2 Skeleton generator — `swiyu-issuer-web/spa/src/app/features/credential-offers/claim-skeleton.ts`

A pure function `buildClaimSkeleton(schema): unknown`. Best-effort:

- For `type: object`, emit an object with one entry per `properties` key (or per `required` if `properties` is absent), recursing.
- For scalars, emit sentinels: strings → `"REPLACE_ME"`, numbers → `0`, booleans → `false`. If `enum` is present, use its first member. Respect simple `format`/`const` where trivially derivable.
- For `array`, emit `[]` (or a single skeleton element if `items` is a simple schema).
- For constructs it cannot resolve (`$ref`, `oneOf`/`anyOf`/`allOf`, deep combinators), fall back to `{}` for that node.

Unit-test this directly (vitest) against representative `claim_schema` shapes — flat object, nested object, enum, required-without-properties, and a `oneOf` that must fall back. This is the most logic-heavy SPA piece and the easiest to test in isolation.

### 3.3 Create-offer store — `credential-offer-create-store.ts`

Holds wizard state across the routed steps: selected `issuerId`, selected `credentialTypeId`, the editor's current `claims` string, `expiresInSeconds`, and the in-flight/submit status. Exposes the create action that POSTs to `/api/issuers/{issuerId}/credential-offers` and stores the one-time result (`id`, `pre_auth_code`, `offer_deeplink`, `expires_at`) for the result step. The result must survive only in memory and never be re-fetched.

Because the result is one-time, do **not** reuse the existing operation-task polling pattern — creation returns the full result synchronously (`201`), so a single request suffices.

### 3.4 Wizard component(s) + routing

Full-page routed steps. Add to `swiyu-issuer-web/spa/src/app/app.routes.ts`:

```ts
{ path: 'credential-offers/new', loadComponent: () => import('./features/credential-offers/credential-offer-create').then(m => m.CredentialOfferCreate) }
```

`CredentialOfferCreate` is the wizard host. Use a `step` signal (or child routes `new/type`, `new/edit`, `new/result`) and render one step at a time; routed sub-paths are preferred so the browser back button maps to steps. Three steps:

1. **Issuer + type** — a `p-select` for issuer (reuse `IssuersStore`, prefer auto-select when exactly one issuer exists, matching `credential-offers-list.ts`) and a dependent `p-select` for credential type, disabled until an issuer is chosen and repopulated from `CredentialTypesStore.loadFor(issuerId)` when the issuer changes. "Next" enabled when both are chosen; on Next, fetch the type's schema.
2. **Edit** — mount `JsonEditor` seeded with `buildClaimSkeleton(schema)` and the fetched `schema`; an optional `expires_in_seconds` `p-inputnumber` defaulting to 600 (bounded 60–3600). "Submit" disabled while the editor reports schema-invalid. On submit, call the store's create action and advance to step 3.
3. **Result** (terminal) — see 3.6.

Mirror `issuer-create.ts` for component shape, form handling, and i18n usage.

### 3.5 `QrCode` component — `swiyu-issuer-web/spa/src/app/shared/qr-code/qr-code.ts`

Add `qrcode` to `package.json`. Thin standalone component: input `value` (string), renders an SVG via `QRCode.toString(value, { type: 'svg' })` bound into the template (e.g. `[innerHTML]` with a sanitized SVG, or an `<img>` from a data-URL). No outputs.

### 3.6 Result step

Terminal page: the structured offer attributes (`id`, `expires_at`), the `pre_auth_code` and `offer_deeplink` each with a copy button, and the deeplink rendered through `QrCode`. An unmissable "shown once — copy it now, it cannot be retrieved" warning. Actions: "Create another" (reset store, route to `new`) and "Back to offers" (route to `/credential-offers`). No navigation that silently loses the code.

### 3.7 Entry point

Add a "New offer" button to the credential-offers list header in `swiyu-issuer-web/spa/src/app/features/credential-offers/credential-offers-list.html` (alongside the refresh action) that routes to `/credential-offers/new`, optionally carrying the currently-selected `issuerId` as a query param to pre-select step 1.

### 3.8 i18n

Add a `credential_offer.create.*` namespace to both `swiyu-issuer-web/spa/public/i18n/en.json` and `de.json`: step titles, field labels/placeholders, the "shown once" warning, copy-button labels, success/error messages. Every user-facing string goes through Transloco.

### 3.9 Tests

- `claim-skeleton.ts`: unit tests (3.2) — the priority.
- Stores: mock the service with `provideHttpClientTesting`, assert load/stale-guard/create behavior, mirroring existing store test style.
- Components: light `TestBed` "creates" smoke tests like `app.spec.ts`; deeper interaction tests where they add value (e.g. type select disabled until issuer chosen, Submit disabled on invalid claims).

### 3.10 Verify Stage 3 (operator)

End-to-end against a real issuer with assigned credential types: pick issuer + type, see the skeleton, edit to valid claims, set a lifetime, submit, and confirm the result page shows a scannable QR plus copyable code/deeplink with the one-time warning. Confirm a scanned/loaded deeplink is accepted by a wallet/holder flow if available.

### 3.11 As built — deviations from the plan above

- **Single-component wizard, not routed sub-paths.** `credential-offer-create.ts` is one routed component (`/credential-offers/new`) with a `step` signal (1→2→3). This is the plan's stated alternative; it was chosen because the one-time result must survive in memory and a single component holds wizard state without a singleton store that would leak across visits. In-wizard "Back"/"Next" move steps; the browser back button returns to the offers list.
- **No separate create-store.** Creation is a single synchronous `201`, so the submit/result logic lives in the component calling `CredentialOffersService.create()` directly (mirrors how `issuer-create` calls its store, minus the optimistic-row/polling machinery which does not apply here). `CredentialTypesStore` (types + schema, with the stale-response guard) was built as planned.
- **i18n split.** The wizard is fully Transloco (`credential_offer.create.*` in `en.json` + `de.json`). The "New offer" button added to the offers list uses a hard-coded English label to stay consistent with `credential-offers-list.html`, which is not yet Transloco-ised. Migrating that list page to Transloco is a separate follow-up.
- **Build config.** Besides Stage 2's `.ttf` loader, `qrcode` is CommonJS, so it is allow-listed via `allowedCommonJsDependencies` in `angular.json` to silence the optimization-bailout warning.
- **Tests.** `claim-skeleton.spec.ts` (10 cases) and `credential-types-store.spec.ts` (4 cases, incl. stale-guard) pass. The wizard component is not unit-tested: it transitively imports Monaco, which does not initialise cleanly under jsdom/vitest — its behaviour is covered by the operator runtime check in 3.10. The repo has one pre-existing failing test (`app.spec.ts`, missing `MessageService` provider) unrelated to this work.

Status: implemented and build-verified (`ng build` clean apart from the pre-existing initial-bundle budget warning). Operator runtime verification (3.10) pending.

---

## Out of scope / notes

- No backend changes — the mgmt API already implements all three upstream routes.
- `did:webvh` is irrelevant here; this is issuance-management UI, not DID method code.
- Bundle size: Monaco is heavy (Stage 2 serves it as on-demand assets, not in the initial bundle); `qrcode` is small. Watch the production budget in `angular.json` (500 kB warn / 1 MB error initial) and keep Monaco out of the initial chunk via the lazy `credential-offers/new` route.
