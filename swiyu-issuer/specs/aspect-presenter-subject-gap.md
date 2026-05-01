# Presenter–subject gap

This document captures decisions and open questions about how
`swiyu-issuer` and the verifiers consuming its credentials close the
gap between the **subject** of a credential (whom the claims describe)
and the **presenter** of a credential (who is actually waving the
wallet at the verifier).

Status: preliminary. Direction agreed; details still open.

## The gap

A credential is a signed document carrying claims about a subject.
Presenting it is a separate act from *being* that subject. Without
explicit mechanism, holder H could hand the credential to anyone —
friend, coercer, thief — and the verifier would scan a perfectly
valid credential. Closing the gap requires layered mechanism: the
credential must be bound to a wallet, the wallet must authenticate
its human user, and the verifier must bridge the wallet to the human
in front of them.

## Three layers

### Layer 1 — Cryptographic holder binding (wallet ↔ credential)

At issuance, the credential is bound to a key pair controlled by the
holder's wallet. In SD-JWT VC this is the `cnf` (confirmation) claim
carrying the holder's public key. At presentation, the wallet emits
a **Key Binding JWT** (KB-JWT) signed by the matching private key,
with the verifier's `nonce` and `aud` baked in. The verifier checks
the KB-JWT signature against `cnf`.

- **Proves**: the wallet presenting the credential is the same
  wallet the issuer issued to. Credentials cannot be silently
  copied between wallets.
- **Does not prove**: that the human holding the wallet is H. A
  stolen unlocked phone, or a coerced holder, will still emit a
  valid KB-JWT.

This layer is non-negotiable infrastructure — the SD-JWT VC profile
assumes it. Every credential `swiyu-issuer` produces carries `cnf`
regardless of what else we do.

### Layer 2 — Wallet device authentication (human ↔ wallet)

The wallet platform gates credential release behind device biometrics
or PIN (Face ID, fingerprint, device PIN). Releasing the credential
requires a per-presentation device check.

- **Proves (transitively, when trusted)**: only the device owner can
  hand a credential out.
- **Does not prove**: that the device owner is H rather than someone
  with whom H shared their PIN, or H under coercion.

This layer is outside our design surface. We inherit it from the
SWIYU wallet; we cannot strengthen it from the issuer side.

### Layer 3 — Subject ↔ human binding at the verifier

Even with layers 1 and 2 in place, the verifier still has to bridge
from "the wallet has presented a valid credential" to "the person at
this gate is H." Standard options:

- **Photo claim on the credential.** The verifier compares the
  picture surfaced by the wallet to the human in front of them.
  This is what physical ID cards do today. Works when verification
  is **attended** (a human attendant doing the comparison).
- **Biometric template on the credential**, matched against a sensor
  at the verifier. Required for **unattended** verification (a
  turnstile-style gate with no human attendant). Heavier deployment,
  privacy-loaded, harder schema.
- **Pair with a separately-presented foundational identity
  credential** (the SWIYU e-ID). The verifier requests two
  credentials and uses the e-ID's photo for the human-side check.
  Lets the residence credential stay slim. See *Linking to the
  SWIYU e-ID* below for how the two credentials are tied together.
- **Human judgement only.** Acceptable for low-stakes
  attendant-staffed scenarios.

## Linking to the SWIYU e-ID

When layer 3 is delivered by pairing with the SWIYU e-ID, the
verifier still needs evidence that the e-ID and the residence
credential refer to the **same person** — not to two different
people whose credentials happen to be in the same presentation. There
are three ways to establish that link, with sharply different
privacy and assumption profiles.

### Approach 1 — Same-wallet binding (cryptographic)

Both credentials are issued to the same wallet, i.e. to the same
`cnf` key. The verifier requests `local-residence-id` and the
SWIYU e-ID in **one OID4VP presentation**. The wallet emits one
KB-JWT; both credentials come back with the same `cnf`. The verifier
observes "same key → same wallet → same person."

- No new claim on the residence credential.
- No identifier in plaintext, so no cross-verifier correlation
  handle.
- Cryptographic, not nominal — the proof is the shared key, not a
  matching string.
- Requires that residence-credential issuance happens to a wallet
  already holding the e-ID (or that the holder authenticates with
  their e-ID at issuance time and the issuer pins the same `cnf`).

This is what SD-JWT VC and OID4VP are designed for. Privacy-
preserving default.

### Approach 2 — Explicit identifier claim on the residence credential

The PoR carries a claim that the verifier matches against the e-ID.
Two natural choices for *what identifier to embed*, with very
different cost profiles.

#### 2a — Stable subject identifier from the e-ID

A claim such as `linked_eid_subject` on the PoR carries a stable
identifier from the e-ID (e.g. its `sub`, or a sectoral identifier).
The verifier asks for both credentials, compares the IDs, accepts on
match.

- Depends on what the SWIYU e-ID profile actually exposes. The
  Swiss e-ID law (BGEID) and the SWIYU profile lean toward
  **sectoral / context-specific identifiers** specifically to prevent
  cross-verifier correlation; if the e-ID does not expose a stable
  subject identifier visible to a commune-context verifier, there is
  nothing to link to.
- A broad-scope identifier (anything resembling AHV-N13) baked into
  every credential becomes a global correlation handle across every
  verifier the holder ever presents to. This pattern fights Swiss
  data-protection norms and the e-ID's own design.
- Issuance-time coupling: BA must know the holder's e-ID identifier
  at issuance time and forward it to `swiyu-issuer`.
- **Survives e-ID replacement**: the identifier is per-person, so
  any e-ID H holds satisfies the link. Holder may legitimately have
  multiple e-IDs (multiple wallet instances, re-issuance after loss,
  key rotation); 2a does not bind to any one of them specifically.

#### 2b — Hashed e-ID `cnf`

The PoR carries a claim such as `linked_eid_holder_key_hash`
containing a hash of the e-ID's `cnf` (the e-ID's holder binding
key). At verification, the verifier asks for both credentials and
checks `hash(eID.cnf) == PoR.linked_eid_holder_key_hash`.

- **No global correlation handle.** The hashed `cnf` is
  wallet-specific and useless outside this exact PoR-and-e-ID
  pairing.
- **Bound to a single (wallet × device × identity) tuple, not to
  the holder.** H may legitimately hold the e-ID in multiple wallet
  instances — phone, tablet, backup device — each with its own
  `cnf`. The PoR is bound to exactly one of these.
- **Operationally fragile under e-ID replacement.** If H removes
  the bound e-ID instance from the wallet (lost device, key
  rotation, replacement after expiry), the PoR's signatures still
  validate but the embedded link goes stale. The credential
  becomes operationally dead — silent failure at the verifier, with
  no in-wallet warning.
- **No protocol-level signal** from wallet to issuer when an e-ID
  is removed; the issuer cannot pre-emptively revoke. Mitigations
  are all unsatisfying: re-issue on every e-ID change (operational
  friction, depends on H remembering), or H artificially keeps the
  old e-ID (bad UX, defeats security hygiene).
- Issuance-time coupling: BA forwards the e-ID's `cnf` (read from
  the OID4VP presentation it just verified) to `swiyu-issuer` along
  with the credential request; the management API needs a
  `linked_eid_holder_key` field.

#### Costs common to both 2a and 2b

- **Verifier behaviour is `vct`-specific.** A generic SD-JWT VC
  verifier validates signatures, KB-JWTs, freshness, and status. It
  does **not** know to compare a claim on credential A against a
  claim or `cnf` of credential B. That cross-credential check is a
  custom rule.
- **Every verifier deploying for this `vct` must implement the
  rule.** Ski lift A, ski lift B, the cash desk at the swimming
  pool — each integrator either rolls their own or pulls in a
  `vct`-specific extension.
- **The rule must be discoverable.** It belongs in the `vct`'s
  SD-JWT VC Type Metadata document (or an external policy doc).
  Without that, integrators read source code or ask the commune.
- **No standard pattern exists yet.** If the Swiss e-ID community
  defines a generic "linked credential" pattern with a canonical
  claim name and verifier rule, generic verifiers can support it
  once. Until then, it is bespoke per `vct`.

### Approach 3 — Selective-disclosure refinement

Either variant of approach 2 can be made selectively disclosable
using SD-JWT's selective disclosure mechanism. The identifier (or
hash) is present in the credential but disclosed only when the
verifier explicitly requests it.

- For 2a, this mitigates correlation by limiting which verifiers
  ever see the stable subject identifier.
- For 2b, the privacy benefit is smaller (the hash is already
  wallet-specific), but disclosure can still be reserved for
  verifiers that genuinely need the link check.
- Does not address the operational fragility of 2b under e-ID
  replacement, nor the verifier-side complexity common to approach
  2.

### Summary

| Dimension                  | 1a                          | 1b                          | 2a                            | 2b                              |
|----------------------------|-----------------------------|-----------------------------|-------------------------------|---------------------------------|
| Bound to                   | Same wallet key             | Same presentation           | Holder identity               | One e-ID instance               |
| Survives e-ID replacement  | If wallet preserves key     | Yes                         | Yes                           | No                              |
| Multiple e-IDs by holder   | Per-credential, transparent | Per-presentation, ok        | All satisfy the link          | Only the bound instance does    |
| Privacy risk               | None beyond SD-JWT VC       | Same                        | Cross-verifier correlation    | Wallet-specific hash; minimal   |
| Verifier complexity        | Generic OID4VP              | Generic OID4VP              | Generic + `vct`-specific      | Generic + `vct`-specific        |
| Wallet policy assumption   | One key per holder          | None                        | None                          | None                            |
| Standards alignment        | First-class                 | First-class                 | Bespoke until standardised    | Bespoke until standardised      |

## Issuance flow and `cnf` ownership

The actors at issuance time, in the deployment shape v0.1.0 targets:

- **Holder H** — the resident.
- **Business application BA** — the commune's web service H interacts
  with. Operates as a **verifier of the e-ID** in this flow.
- **`swiyu-issuer`** — the credential issuer. Called by BA via the
  management API. Does **not** see the e-ID directly.
- **Wallet** — H's SWIYU wallet, holding the e-ID and (after
  issuance) the PoR.

The flow:

1. H opens BA, requests a PoR.
2. BA initiates an OID4VP request asking the wallet for the SWIYU
   e-ID with the claims it needs.
3. Wallet returns a presentation; BA validates signatures, KB-JWT,
   trust chain, freshness.
4. BA looks up H in the commune's resident register; confirms
   residency.
5. BA calls `swiyu-issuer`'s management API with `vct`, claims,
   and other offer metadata.
6. `swiyu-issuer` returns a credential offer (pre-auth code,
   deeplink).
7. BA renders the deeplink/QR back to H in the same browser session.
8. Wallet picks up the offer, runs OID4VCI, supplies a
   **wallet-chosen key** as proof of possession.
9. `swiyu-issuer` mints the PoR bound to that key — it becomes the
   PoR's `cnf`.

Two structural points fall out.

### `swiyu-issuer` cannot enforce shared `cnf`

The wallet picks the key for the PoR's `cnf` at step 8. The issuer
cannot dictate whether the wallet uses the same key as the e-ID or
a fresh one. This is a property of the SD-JWT VC + OID4VCI contract,
not a missing feature of `swiyu-issuer`.

Two wallet policies are common in the wider ecosystem:

- **One key per holder** — wallet reuses the same key across all
  credentials. Same `cnf` everywhere. Convenient; weaker on
  cross-verifier correlation resistance.
- **One key per credential** — wallet generates a fresh key per
  credential. Different `cnf` per credential. Privacy-preserving
  default for SD-JWT VC; prevents cross-verifier correlation via
  the public key.

The SWIYU wallet's actual policy here is not yet confirmed (see
*Open*).

### What approach 1 actually delivers depends on that policy

Approach 1 has two sub-flavours that differ on what evidence the
verifier has:

- **1a — Same-`cnf` check.** Verifier compares `cnf` on the e-ID
  with `cnf` on the PoR; equality means same key, same wallet, same
  person. Works only if the wallet uses one key per holder.
- **1b — Same-presentation check.** Both credentials arrive in one
  OID4VP presentation, each with its own valid KB-JWT signed by its
  own holder binding key. The verifier trusts the wallet to
  assemble that presentation only from credentials issued to its
  user. Operational/transactional binding, weaker than 1a but works
  regardless of key policy.

Either is acceptable for the v0.1.0 assurance bar. The verifier
ecosystem must support **1b** in any case — key-per-credential
wallets are standards-aligned and we should not assume against them.

### The trust anchor at issuance time is BA, not `swiyu-issuer`

The link from the e-ID identity to the freshly-issued PoR is
established at BA, in BA's audit trail: *"I verified an e-ID with
claims X, Y, Z; I requested a PoR for that person."* It is not
established cryptographically between the e-ID's `cnf` and the
PoR's `cnf` (the wallet may have chosen different keys). The
implicit operational invariant — *the wallet that picks up the
offer is the same wallet that just presented the e-ID* — holds in
practice because BA hands the offer back through the same browser
session that hosted the OID4VP exchange.

This is why the v0.1.0 management API takes the resident's claims
from BA without seeing the e-ID itself: BA owns the verification
step; `swiyu-issuer` owns the issuance step; they meet at the
management API.

## v0.1.0 decision

The first issued credential, `urn:communal:local-residence-id`,
ships **without a portrait claim**. The schema in
[`impl_credential_schema.md`](impl_credential_schema.md) carries
identity-bearing claims (`family_name`, `given_name`, `birth_date`,
`address`, `valid_until`) but no image.

Layer 1 is in place by virtue of the SD-JWT VC format. Layer 2 is
inherited from the SWIYU wallet. Layer 3 is **explicitly deferred**:
v0.1.0 does not commit to *how* the ski-lift cash desk closes the
human-side gap.

For e-ID linking, v0.1.0 commits to **approach 1**. No
e-ID-referencing claim is added to
`urn:communal:local-residence-id`. The link is established at
presentation time — either cryptographically through a shared `cnf`
(sub-flavour 1a) or operationally through the same-presentation
invariant (sub-flavour 1b), depending on the SWIYU wallet's key
policy. Either is acceptable for the v0.1.0 assurance bar.
Approaches 2 and 3 are revisited only if a concrete verifier flow
appears that cannot combine credentials in one presentation, *and*
the SWIYU e-ID profile is shown to expose a stable subject
identifier safe to embed.

This is acceptable because:

- v0.1.0 is the walking-skeleton scope. End-to-end verifier behaviour
  for the local-residence-id is not yet defined.
- The ski-lift use case is attended at v1; the cash-desk attendant
  performs an informal name check.
- The intended assurance bar — "deters casual lending among teens"
  for a discounted ski pass — is not high enough to justify a
  portrait claim in the walking skeleton.
- Adding a portrait claim later is an additive, non-breaking change
  to the schema (a new optional property), so deferring costs us
  nothing structural.

## Residual risk

Even with all three layers in place, three categories of risk remain
and are mitigated operationally rather than at the protocol level:

- **Coerced holder.** A holder forced to unlock and present is
  undetectable at the verifier. Mitigation is fraud monitoring and
  revocation, not protocol.
- **Wallet platform mis-binding.** A platform flaw that binds a
  fresh device to H's identity (e.g., via a flawed account-recovery
  path) collapses layer 2 silently. The issuer cannot detect this.
- **Stale photo / stale claims.** Layer 3 photo can be out of date.
  `valid_until` doesn't help here; addressed by issuance hygiene
  (e.g., re-issuance triggers) on the issuer side.

## Open

- **Final assurance level for the ski-lift use case.** The bar drives
  every layer-3 decision. Current placeholder: "deters casual
  lending among teens" — explicit confirmation needed before v1
  ships.
- **Whether to add a portrait claim** to
  `urn:communal:local-residence-id` post-v0.1.0. Trigger: a
  cash-desk pilot that exposes the human-check gap.
- **Whether to lean on the SWIYU e-ID as the layer-3 anchor**
  rather than baking a portrait into every commune-issued credential.
  See the linking discussion below; lean is "yes, prefer e-ID
  pairing" once the SWIYU e-ID ecosystem is mature.
- **Unattended verification (turnstile gates).** Out of scope for
  v0.1.0; would require biometric or e-ID-paired verification flows
  and is a substantially bigger design conversation.
- **SWIYU e-ID claim profile.** Whether the SWIYU e-ID exposes a
  stable subject identifier that a commune-context verifier can
  read. Resolving this is a precondition for ever revisiting
  approaches 2 or 3 of e-ID linking; today we have no authoritative
  source. v0.1.0 does not depend on the answer.
- **SWIYU wallet key policy.** Whether the SWIYU wallet uses one
  key per holder (approach 1a applies) or one key per credential
  (only approach 1b applies). Determines what evidence verifiers
  actually see; not blocking for v0.1.0 since both 1a and 1b are
  acceptable. Worth confirming with whoever maintains the wallet.
- **Issuance-time e-ID authentication.** Whether residence-credential
  issuance is gated on a successful SWIYU e-ID authentication at BA
  (so the residence credential is issued to a wallet that just
  presented the e-ID in the same session). Required for approach 1
  to deliver real assurance; the management API does not currently
  model this — BA enforces it. Lands as part of BA's flow, not
  `swiyu-issuer`'s, but worth tracking here.
