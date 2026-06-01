# Credential Management UI

This document specifies the web UI for issuing and managing credentials in the `swiyu-issuer-web` admin SPA: the navigation, the credential-offer creation flow, the management of offers and issued credentials, and the BFF endpoints these screens need. It builds on the management API modelled in `swiyu-issuer` — see the credential-management aspect (`../../swiyu-issuer/specs/aspect-credential-management.md`), the credential-type aspect (`../../swiyu-issuer/specs/aspect-credential-type.md`), and the management-API implementation (`../../swiyu-issuer/specs/impl_api_management.md`). The SPA and BFF architecture (SPA talks only to the BFF; the BFF is a thin, auth-injecting proxy to the management API) is the same one already used for the issuer screens.

Status: preliminary; living document.

## Scope

The admin SPA acts as a stand-in for a *business application* (BA): it is the operator-facing tool that asks the issuer to mint credentials and that manages their lifecycle afterwards. This document covers two operator activities and the screens behind them: creating a credential offer, and managing the offers and issued credentials of an issuer.

Out of scope here:

- **Credential-type authoring.** Credential types (their `vct`, `claim_schema`, `display`, and assignment to issuers) are assumed to already exist, provisioned via the CLI or elsewhere. The management API for creating and assigning types is present, so a type-authoring surface can be added later; it is not part of this work.
- **Offer delivery automation.** How a real BA transports an offer to a holder (email, SMS, push, portal) is the BA's concern. This tool only presents the offer for manual delivery (see *Offer delivery*).
- **The OID4VCI wire protocol and wallet pickup.** The holder/wallet side and the asynchronous minting of the credential live entirely in `swiyu-issuer`; the SPA never participates in it.

## Background: offers versus credentials

The single most important distinction for this UI is between a **credential offer** and an **issued credential**. They are different resources with different lifecycles, and the operator must be able to tell them apart at a glance.

A **credential offer** is an *invitation*. The operator creates it **synchronously**: the SPA posts the chosen credential type and claims, and the management API responds immediately with an `openid-credential-offer://` deeplink (suitable for a QR code) plus a one-time pre-authorisation code. No SWIYU registry is touched at this point, and there is no asynchronous saga to track — unlike issuer create/deactivate/rotate-keys, offer creation is a plain request/response.

An **issued credential** is the *real credential in a holder's wallet*. It comes into existence **asynchronously and holder-driven**: when the holder's wallet scans the offer and redeems the pre-authorisation code through OID4VCI, the management API mints the credential, the originating offer transitions to `issued`, and a new issued-credential record appears. The operator cannot force or trigger this conversion; it happens when the holder acts. An offer produces at most one issued credential — none if it is cancelled or expires before pickup.

The two are linked: an issued credential carries the `credential_offer_id` of the offer it came from, and an offer gains an `issued_at` timestamp once collected. The UI cross-links them.

State vocabularies differ and warrant distinct presentation:

- **Offer:** `pending`, `issued`, `expired`, `cancelled`. The `expired` view is derived from `expires_at`; it is not a stored state.
- **Issued credential:** `active`, `suspended`, `revoked`, plus a derived `expired` view that is never stored as a state.

## Navigation

A left-menu item **Credentials** with two submenu items:

- **Create** — opens the offer-creation wizard.
- **Manage** — opens the management screen.

### Issuer context

Both activities are issuer-scoped. Rather than re-selecting the issuer inside every dialog and on every screen, the operator picks an issuer **once** for the whole Credentials area, and both Create and Manage operate on that selection. The selection persists while the operator moves between Create and Manage.

## Create flow

Create is a **dedicated page / wizard**, not a dialog: the result includes a QR code and the claims input can be sizeable, both of which are cramped in a dialog.

Steps:

1. **Issuer** — taken from the issuer context (selectable if not already set).
2. **Credential type** — chosen from the types the issuer is allowed to mint, fetched via `GET /api/issuers/{id}/credential-types`. The operator never types a `vct` directly; the type row supplies the `vct`, `claim_schema`, and default validity.
3. **Claims** — entered as **raw JSON**, validated server-side against the type's `claim_schema`. A structured, schema-driven form is a possible later refinement; the raw-JSON editor is the initial input because it is robust for any schema and avoids a generic JSON-Schema form generator.
4. **Submit** — `POST /api/issuers/{id}/credential-offers` with `{ credential_type_id, claims, expires_in_seconds? }`. The call is synchronous; on success it returns `{ id, pre_auth_code, offer_deeplink, expires_at }`.
5. **Result** — a result view presenting the created offer for delivery (see below).

Validation errors from the management API (invalid claims against the schema, out-of-range expiry) are surfaced inline on the claims step; the raw JSON is preserved so the operator can correct it.

### Offer delivery

Delivering the offer to the holder is the BA's job; this tool presents it for manual delivery through the two canonical OID4VCI channels:

- **QR code (cross-device / in-person):** the `offer_deeplink` rendered as a QR code, for the holder to scan with a wallet app on their phone.
- **Deeplink (same-device / remote):** the `offer_deeplink` shown as a copyable field, so the operator can paste it into whatever channel the simulated BA uses (email, chat, a portal link).

The result view shows both, plus the `expires_at`.

A caveat the UI must make visible: the offer deeplink embeds a **one-time, time-limited pre-authorisation secret**. The management API returns `pre_auth_code` exactly once and stores only its hash. Anyone who obtains the link before it is collected or expires can redeem it. For a simulation/test tool this is acceptable and copy-paste delivery is fine; the result view states that the link is single-use, short-lived, and should be sent over a channel the operator trusts.

## Manage flow

A single Manage page for the selected issuer, with **two clearly separated tabs**, each cross-linked to the other.

### Offers tab

Lists the issuer's credential offers via `GET /api/issuers/{id}/credential-offers` (filterable by state). Each row shows state (`pending` / `issued` / `expired` / `cancelled`), the credential type / `vct`, creation and expiry times, and `issued_at` once collected.

Actions:

- **Cancel** a `pending` offer — `POST /api/issuers/{id}/credential-offers/{offer_id}/cancel`.
- **Re-show** the QR / deeplink for a `pending` offer (the deeplink is stored on the offer row; the one-time `pre_auth_code` is not re-issued, but the deeplink remains valid until the offer is collected, cancelled, or expires).
- **View the resulting credential** for an `issued` offer — cross-link into the Credentials tab.

### Credentials tab

Lists the issuer's issued credentials via `GET /api/issuers/{id}/credentials` (filterable by state and `vct`). Each row shows state (`active` / `suspended` / `revoked`, plus a derived `expired` marker), `vct`, issued and expiry times, and a link back to the originating offer.

Actions:

- **Suspend** an `active` credential — `POST .../credentials/{credential_id}/suspend`.
- **Unsuspend** a `suspended` credential — `POST .../credentials/{credential_id}/unsuspend`.
- **Revoke** a credential — `POST .../credentials/{credential_id}/revoke`. Revocation is terminal; the UI confirms before revoking.

### Refresh, not poll

Because the offer-to-credential conversion is holder-driven, there is nothing for the admin side to poll. Both tabs load on open and offer a manual refresh, the same pattern as the issuers list.

## BFF endpoints

The BFF gains thin proxies that forward to the management API with the bearer token injected, mirroring the existing issuer proxies. Paths drop the `/v1` segment, consistent with the existing `/api/issuers` mapping.

| SPA need | BFF route | Management API |
| --- | --- | --- |
| List an issuer's credential types | `GET /api/issuers/{id}/credential-types` | `GET /api/v1/issuers/{id}/credential-types` |
| Create an offer | `POST /api/issuers/{id}/credential-offers` | `POST /api/v1/issuers/{id}/credential-offers` |
| List offers | `GET /api/issuers/{id}/credential-offers` | `GET /api/v1/issuers/{id}/credential-offers` |
| Get one offer | `GET /api/issuers/{id}/credential-offers/{offer_id}` | `GET /api/v1/issuers/{id}/credential-offers/{offer_id}` |
| Offer status | `GET /api/issuers/{id}/credential-offers/{offer_id}/status` | `GET /api/v1/issuers/{id}/credential-offers/{offer_id}/status` |
| Cancel an offer | `POST /api/issuers/{id}/credential-offers/{offer_id}/cancel` | `POST /api/v1/issuers/{id}/credential-offers/{offer_id}/cancel` |
| List issued credentials | `GET /api/issuers/{id}/credentials` | `GET /api/v1/issuers/{id}/credentials` |
| Get one credential | `GET /api/issuers/{id}/credentials/{credential_id}` | `GET /api/v1/issuers/{id}/credentials/{credential_id}` |
| Suspend | `POST /api/issuers/{id}/credentials/{credential_id}/suspend` | `POST /api/v1/issuers/{id}/credentials/{credential_id}/suspend` |
| Unsuspend | `POST /api/issuers/{id}/credentials/{credential_id}/unsuspend` | `POST /api/v1/issuers/{id}/credentials/{credential_id}/unsuspend` |
| Revoke | `POST /api/issuers/{id}/credentials/{credential_id}/revoke` | `POST /api/v1/issuers/{id}/credentials/{credential_id}/revoke` |

Query parameters (`limit`, `cursor`, `state`, `vct`) are forwarded as-is. The BFF continues to forward upstream status codes and JSON bodies verbatim so the SPA can distinguish a validation error from a gateway failure.

## Technology notes

- **QR rendering** uses a framework-agnostic JavaScript library (for example `qrcode`) driven from the component, rather than an Angular wrapper component, to avoid Angular-version coupling — the same reasoning applied to the highlight.js choice for the DID-log viewer.
- **i18n** follows the established Transloco setup; all operator-facing strings are keyed (`credential.*`).
- **PrimeNG** supplies the tables, tabs, dialogs, and form controls already used elsewhere in the SPA.

## Build sequence

The feature is delivered in slices so each is independently demoable:

1. **BFF proxy layer** — the credential-type, offer, and credential endpoints above.
2. **Navigation, issuer context, and the Create flow** — the synchronous offer wizard ending in the QR/deeplink result view. This is the most self-contained slice and exercises the full create-an-offer path.
3. **Manage flow** — the Offers and Credentials tabs, their actions, and the cross-links.

## Open points

- **Schema-driven claims form.** The raw-JSON claims editor is the starting input. Whether to later generate a form from `claim_schema` (and how much of JSON Schema to support) is deferred.
- **Issuer context placement.** The exact UI for selecting and persisting the issuer across the Credentials area (a selector in the page header versus a shared control) is to be settled during implementation.
- **Re-showing an offer.** Whether the management API exposes enough on the offer row to reconstruct a scannable artifact after creation, or whether re-showing is limited to the stored deeplink, should be confirmed against the offer GET response during implementation.
