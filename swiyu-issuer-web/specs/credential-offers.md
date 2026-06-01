# Credential Offers — list view

This document specifies the **Credential Offers** page in the `swiyu-issuer-web` admin SPA and the two BFF endpoints it depends on. It is a first, narrow slice of the broader Credentials area outlined in [`credential-management-ui.md`](credential-management-ui.md): the list/browse view of an issuer's credential offers, with no creation or lifecycle actions yet.

Status: preliminary; living document.

## Scope

In scope:

- A left-menu item **Credential Offers** that opens a dedicated page.
- The page shows two sections: an **issuer picker** at the top and a **credential offers table** below.
- The list of offers is loaded from the management API via the BFF; the table renders one row per offer with timestamps and a state badge.
- Cursor-based "Load more" pagination.
- A refresh action that drops all loaded state and reloads page 1.
- Two BFF endpoints: a paged list (without claims) and a single-offer detail (with claims).

Out of scope here (deferred):

- The **creation wizard** (`POST /api/issuers/{id}/credential-offers` and the QR / deeplink result view). Covered by [`credential-management-ui.md`](credential-management-ui.md) and will land separately.
- The **offer-detail UI** (a drawer or sub-page showing the full offer, including claims). The BFF endpoint to back it ships in this slice, but no SPA UI consumes it yet — the table's kebab column is a visual placeholder.
- A **state filter** above the table (the mgmtapi supports `?state=pending|issued|cancelled|expired`; the UI does not surface it yet).
- **Search by offer id** in the toolbar. The mgmtapi has no search parameter; a client-side filter over loaded pages is possible but deferred.
- **Polling for pending offers.** The `pending → issued` transition happens when the wallet redeems the pre-authorisation code, asynchronously. The operator triggers a refresh manually.
- **Cancel / re-show actions** on a row. Covered by the Manage flow in [`credential-management-ui.md`](credential-management-ui.md).

Divergence from [`credential-management-ui.md`](credential-management-ui.md) worth flagging: that document proposes a global "Credentials" area with persistent issuer context across Create / Manage submenus. The slice in this document keeps the issuer picker **inside the Credential Offers page**, with the selection encoded in the URL. When the Create flow and a Manage page with multiple tabs land, the issuer-context model from `credential-management-ui.md` is the target end state; the per-page picker is an intermediate that costs nothing to evolve into a shared context later.

## Navigation

A new left-menu item **Credential Offers**, placed directly below the existing **Issuers** entry, with the `pi pi-fw pi-send` icon. Clicking it routes to `/credential-offers`.

The label is a plain string today, matching the existing "Issuers" entry; both move to translation keys when the menu is internationalised.

## Route

```
/credential-offers?issuerId=<id>
```

- The optional `issuerId` query parameter holds the bare issuer id (the same form used in `/issuers/:id`).
- The **URL is the source of truth** for the current selection. The picker reflects the parameter; user picks write back to the URL.
- **Auto-select rule:** if the URL has no `issuerId` and the tenant has exactly one issuer, the SPA replaces the URL with that issuer's id. `replaceUrl: true` so the auto-select does not pollute browser history. Explicit user picks push history entries (back/forward navigates between past selections).
- A `?issuerId=` pointing at an issuer that does not exist resolves to "no selection" — the table is hidden, the picker stays empty. The URL is left untouched so the operator notices their bookmark is stale rather than having it silently rewritten.

## Page structure

```
┌─ Credential Offers ──────────────────────────────── [↻] ┐
│                                                          │
│  ┌─ Issuer ──────────────────────────────────────────┐  │
│  │  Select the issuer whose credential offers …      │  │
│  │  [ autocomplete ────────────────────── ▾ ]        │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌─ Credential offers  ⓜ ─────────────────────────────┐ │
│  │  ┌────────────────────────────────────────────┐    │ │
│  │  │  table or empty state                       │    │ │
│  │  └────────────────────────────────────────────┘    │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

A page header with title and a refresh button (disabled until an issuer is selected), then two visually distinct sections: the picker on top, the offers table below.

### Issuer picker

A filterable **autocomplete** (PrimeNG `p-autocomplete`), chosen over a `p-select` so that tenants with > 20 issuers do not have to scroll a long popup. Properties:

- Filter source: the issuer list cached by the existing `IssuersStore`. No extra fetch when the user switches between the Issuers page and this page.
- Filter predicate: case-insensitive substring match on either `display_name` or `did`.
- `forceSelection`: the user must pick from the list, cannot type free-form text.
- `dropdown`: a chevron opens the unfiltered list, so the picker is still usable as a flat list when the tenant has few issuers.
- `showClear`: the operator can clear the selection; doing so removes `?issuerId=` from the URL.
- Each suggestion row shows the issuer's display name, its DID truncated with a tooltip, and a state tag (`active` / `inactive`).

States the picker section renders:

| Condition | Rendered |
| --- | --- |
| `IssuersStore` is loading and the cache is empty | Inline spinner + "Loading issuers…" |
| `IssuersStore` reports an error | `p-message severity="error"` + a Retry button |
| Issuers list is empty | `p-message severity="info"` with "No issuers yet. Create one before issuing credential offers." |
| Otherwise | The autocomplete |

### Credential offers table

Empty until an issuer is selected. When no selection is set, the section shows a muted centred message with an upward arrow: "Select an issuer above to view its credential offers."

Once an issuer is selected, the SPA fetches the first page from the BFF and renders a compact (`p-datatable-sm`) table with these columns, all derived from `CredentialOfferSummary` (see *BFF*):

| Column | Source | Notes |
| --- | --- | --- |
| Offer ID | `id` | Monospaced, truncated, tooltip with the full id |
| VCT | `vct` | Monospaced, muted, truncated |
| State | `state` | `p-tag`, colour-mapped: `pending` → info, `issued` → success, `cancelled` → secondary, `expired` → warn |
| Created | `created_at` | Plain ISO string for the first slice; a relative pipe lands later |
| Expires | `expires_at` | As above |
| Issued | `issued_at` | "—" when `null` |
| (actions) | — | Kebab placeholder; wired to "View details" / "Cancel" in a later slice |

The table header carries a count badge (`offers.length`). The footer slot contains a **Load more** button shown only when the last response carried a non-null `next_cursor`.

The page-header **refresh** button drops all loaded pages and re-fetches page 1. There is no incremental "refresh each loaded page" mode.

## BFF endpoints

Two endpoints, both proxying to the management API. The BFF reshapes responses to omit large fields from the list view but does not transform field names or semantics.

### List

```
GET /api/issuers/{issuer_id}/credential-offers
    ?limit=<1..100>          (optional, default 25)
    &cursor=<opaque>         (optional)
```

Proxies to mgmtapi `GET /api/v1/issuers/{issuer_id}/credential-offers` (operationId `listCredentialOffers`, see `swiyu-issuer/openapi-mgmt.yml`). The BFF forwards `limit` and `cursor` verbatim; `state` is **not** forwarded in this slice (no state filter UI yet).

Response (`200`):

```json
{
  "items": [ { "...CredentialOfferSummary..." } ],
  "next_cursor": "<opaque>" | null
}
```

`CredentialOfferSummary` is the upstream `GetCredentialOfferResponse` with `claims` stripped:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Prefixed offer id (`offer_…`) |
| `issuer_id` | string | |
| `vct` | string | SD-JWT VC type identifier |
| `credential_type_id` | string? | Bare base58 id; absent on legacy rows. Forwarded so the SPA can later look up credential-type metadata without an extra round trip |
| `state` | enum | `pending`, `issued`, `cancelled`, `expired` |
| `expires_at` | datetime | |
| `created_at` | datetime | |
| `issued_at` | datetime? | `null` until the wallet redeems the offer |
| `cancelled_at` | datetime? | `null` until cancelled |

Stripping `claims` keeps list payloads small even on tenants with large claim objects, and avoids paying for serialisation on a column the table does not display.

Error mapping: 400 / 401 / 404 from upstream pass through with their bodies replaced by the BFF's standard error envelope. The same mapping the issuer routes already use.

### Detail

```
GET /api/issuers/{issuer_id}/credential-offers/{offer_id}
```

Proxies to mgmtapi `GET /api/v1/issuers/{issuer_id}/credential-offers/{offer_id}` (operationId `getCredentialOffer`). Returns the full `CredentialOfferSummary` plus `claims` (an arbitrary JSON object — `additionalProperties: true` in the upstream schema). No reshaping.

This slice ships the endpoint so the SPA detail surface can be added without a BFF round-trip. No SPA UI consumes it yet.

## Pagination

The management API uses cursor-based pagination (`?limit=…&cursor=<opaque>`, response `{ items, next_cursor }`). Cursors are opaque on the management-API side: clients must not parse or construct them, and the server rejects anything it did not emit.

**BFF: forward 1:1.** The BFF takes `limit` and `cursor` as query parameters and passes them through; the response shape — `items` plus `next_cursor` — is forwarded unchanged. The BFF does not aggregate pages server-side. Aggregating would be tempting (one call from the SPA, no client-side paging logic), but a busy issuer with thousands of offers would block the BFF for seconds, return a megabyte-scale payload, and defeat the per-item `claims` stripping the list endpoint exists for. Pure proxy is cheaper and matches the contract the upstream already advertises.

The BFF also does not mint its own cursors. There is no per-page transformation that warrants a separate pagination state; stripping `claims` is per-item, and `next_cursor` from upstream remains valid for the next BFF call without rewriting.

**SPA: accumulate behind "Load more".** The store keeps two signals: `items: signal<CredentialOfferSummary[]>` and `nextCursor: signal<string | null>`. The three operations:

| Operation | Effect |
| --- | --- |
| `loadFor(issuerId)` | Issues a request with no cursor. **Replaces** `items` with the response page and stores `next_cursor`. |
| `loadMore()` | Issues a request with the stored cursor. **Appends** the response items and overwrites `next_cursor`. |
| `refresh()` | Same as `loadFor(current_issuer_id)` — drops accumulated state, fetches page 1. |

The footer "Load more" button is rendered only when `nextCursor() !== null` and is disabled while a fetch is in flight. Page-number navigation is not offered: cursors do not support random access, and synthesising a page count would require either fetching the whole list up front or guessing.

**Race on issuer switch.** If the operator picks issuer A and switches to B before A's response arrives, A's response must not overwrite B's state. The store tags every in-flight request with the issuer id it was issued for; on response, the store discards the result if the tag no longer matches the current selection. `loadFor` always replaces the tag; `loadMore` reads the tag at request time and re-checks on response. The same rule covers a refresh-then-switch sequence.

**Stale cursor.** If the upstream rejects a cursor (e.g., after a server-side schema change), `loadMore` surfaces a generic "could not load more" error. Recovery is to refresh the page, which drops the cursor and starts over from page 1.

**Why not numbered pages.** Classic "1, 2, …, 32 — Prev / Next" pagination is good UX but does not fit a cursor API: jumping to page 32 requires either offset-based access or a total-count field, and the management API offers neither (cursors are opaque, totals are not returned). A workable subset is **Prev / Next without jump-to-page**, implemented as a client-side stack of visited cursors that the SPA pops on Prev — that pattern is not adopted for this slice. The use case that classic pagination answers ("operator looks for something specific") is what the deferred state filter and offer-id search are intended to address; once those land, deep pagination is rarely needed. Swapping "Load more" for a Prev / Next stack later is a contained store change — the BFF endpoint and the table columns do not move.

**Page size.** The SPA sends no explicit `limit`; the management API's default (25) applies. A tunable page size is a follow-up if operators ask for it.

## SPA architecture

A new feature folder, `spa/src/app/features/credential-offers/`, with:

- `credential-offers-service.ts` — HTTP client with `list(issuerId, { limit?, cursor? })` and `get(issuerId, offerId)`, mirroring the existing `IssuersService`.
- `credential-offers-store.ts` — provides per-issuer paging state: `loadFor(issuerId)` (resets + first page), `loadMore()` (appends), `refresh()` (drops + reloads). Holds the latest `next_cursor`. Exposes signals: `items`, `loading`, `error`, `hasMore`.
- `credential-offers-list.ts` / `.html` / `.scss` — the page component. An `effect()` keyed on `selectedIssuer()` calls `store.loadFor(id)` whenever the selection changes (covers deep-links, auto-select, manual picks). The refresh button calls `store.refresh()`; the footer button calls `store.loadMore()`.

The component imports the existing `IssuersStore` to feed the picker, and the new `CredentialOffersStore` to feed the table.

## Decisions, briefly

The following were considered and **not** taken for this slice. They are listed here so a future iteration does not have to re-litigate them:

- **Issuer picker dropdown vs. autocomplete.** Filterable `p-select` works at small scale but becomes unwieldy past ~20 issuers; `p-autocomplete` keeps the UI calm regardless of size and is a one-line change away from `p-select`.
- **Issuer selector dialog.** Considered for scale beyond ~50 issuers; not adopted because the autocomplete handles the expected range without an extra click.
- **Two-step page (pick issuer → navigate to offers page).** Rejected: adds a navigation step for what is one task; switching issuers should be one interaction.
- **Refresh that re-fetches each loaded page.** Rejected for the first slice in favour of "drop and reload page 1", matching the Issuers page and avoiding a stateful refresh path.
- **Polling pending offers.** Not adopted; `pending → issued` is wallet-driven and unpredictable, and the operator can refresh manually.

## Open questions

- **Stale `?issuerId=` cleanup.** The current behaviour is to leave the URL alone when the parameter does not resolve to a known issuer, so the operator notices a stale bookmark. An alternative is to silently drop the parameter and show a "the issuer you selected no longer exists" notice. The current choice errs on the side of preserving operator-supplied state.
- **Picker behaviour after the operator clears a sole-issuer tenant.** Today the auto-select effect re-applies. Acceptable because there is nothing else to pick, but worth re-examining if a "respect explicit clear" model is ever wanted.
- **Date formatting.** ISO strings are rendered as-is until a date pipe (relative or locale-aware absolute) is added. Decide alongside the broader date-formatting strategy of the SPA.
