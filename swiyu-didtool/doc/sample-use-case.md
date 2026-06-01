# Using `didtool` to onboard a SWIYU issuer

kacon gmbh is a small Swiss consulting company that runs courses on IT architecture. Until now, students have received a paper confirmation of attendance at the end of each course. Going forward, kacon gmbh wants to hand them a verifiable credential in the Swiss Trust Infrastructure (SWIYU) instead.

This tutorial walks through that onboarding end-to-end with `didtool`. If you are setting up your own organisation as an issuer or verifier, the same steps apply.

## The registries in the SWIYU ecosystem

1. **Base Registry**

   Stores organisational metadata about registered participants — legal name, language preference, contact details — each identified by a unique **Business Partner ID** (a UUID). The Base Registry is the source of truth for *who* is on SWIYU.

   *In this tutorial:* kacon gmbh is registered as a participant here and assigned a Business Partner ID (later referred to as `SWIYU_PARTNER_ID`).

2. **Identifier Registry**

   Stores DID logs — the public, append-only history of every registered DID. This is where DIDs *live*.

   *In this tutorial:* the DID we create with `didtool did create` is published here, together with later log entries from key rotations and the eventual deactivation.

3. **Trust Registry**

   Stores **Trust Statements** — signed assertions, issued by SWIYU, that bind a DID to organisational identity (legal name per locale, state-actor flag, status-list pointer for revocation). Verifiers consult it to decide whether a given DID belongs to a participant SWIYU vouches for.

   *In this tutorial:* after SWIYU's manual onboarding, a Trust Statement linking kacon gmbh's DID back to kacon gmbh's Base Registry entry is published here.

4. **Status List Registry**

   Stores **status lists** — used by issuers to revoke previously-issued credentials or Trust Statements, and by verifiers to confirm an item is still valid.

   *In this tutorial:* the Trust Statement that SWIYU issues for kacon gmbh's DID points into a SWIYU-managed status list here — that is how revocation of the Trust Statement would be signalled. Later on, once kacon gmbh starts issuing verifiable credentials to its students, kacon gmbh will publish its own status lists in this registry to be able to revoke individual credentials.

## Becoming a business partner in SWIYU

kacon gmbh first has to become a registered **business partner** (also called *business entity*) in the SWIYU ecosystem. The registration process is purely manual; the required steps are described in [Onboarding the swiyu Base & Trust Registry][swiyu-onboarding]. There are two major steps:

1. **Register kacon gmbh in the SWIYU Base Registry.**
   * Outcome:
     * kacon gmbh is registered in the SWIYU Base Registry.
     * kacon gmbh is assigned a unique **Business Partner ID** (a UUID; referred to as `SWIYU_PARTNER_ID` in the rest of this tutorial).

2. **Register kacon gmbh in the SWIYU Trust Registry.**
   * Outcome:
     * kacon gmbh is registered in the SWIYU Trust Registry under a specific DID.
     * SWIYU issued a **Trust Statement** vouching that this DID identifies kacon gmbh (or: that kacon gmbh controls this DID).

## Register kacon gmbh in the SWIYU Base Registry

Registration is done manually through the [ePortal] of the Swiss Confederation. The person who registers kacon gmbh needs a digital identity that ePortal accepts; in this tutorial we use an [AGOV][agov] identity.

After logging in, follow the steps in the [SWIYU onboarding guide][swiyu-onboarding], section 2 *Register Organization*.

A business partner for kacon gmbh is created in the Base Registry and assigned a unique **Business Partner ID** (e.g. `45ff7b48-446f-11f1-b925-a734ec758462`). Write it down, we will use it in later steps.

Next, follow the manual steps described in *Get API keys to access swiyu APIs* of the same guide. Of the credentials you obtain, you need the **Client ID**, the **Client Secret**, and the **Renewal Token** (refresh token) — didtool exchanges the refresh token for a short-lived access token on every run, so you do not paste an access token by hand. Save these and treat the secret and refresh token as secrets.

## Configure `didtool`

* copy `.env.example` to `.env`
* edit `.env` and fill in `SWIYU_PARTNER_ID` and the OAuth2 credentials `SWIYU_TOKEN_URL`, `SWIYU_CLIENT_ID`, `SWIYU_CLIENT_SECRET`, and `SWIYU_REFRESH_TOKEN` from the previous steps

If you work with `direnv`, it automatically populates environment variables from `.env`. Otherwise, source `.env` manually:

```bash
source .env
```

## Create a DID for kacon gmbh

We have to create a DID that we can bind to the business partner kacon gmbh.

```bash
# create a new DID
didtool did create
```

Output:

```
Generated DID: did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
Saved DID log entry: did.jsonl
Keystore hash: 0e616e6729ad
Published to registry: https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/468c4af1-7af1-40ad-a6a5-a0076a8f51e3/did.jsonl
```

Three key pairs are associated with the generated DID. `didtool` generated them and stored them in the `didtool` keystore. You can look them up:

> [!CAUTION]
> The `didtool` keystore writes private keys to disk **unencrypted** (PEM files
> in the keystore directory). This is fine for development against the SWIYU
> integration environment, but **do not use `didtool` for production keys**.

```bash
# list the entries in the key store; includes the entry for the DID we just generated
didtool key list
```

Output:

```
0e616e6729ad  did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

```bash
# show the public keys associated with the DID
didtool key show --did 0e616e6729ad
# or:
didtool key show --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

This lists the three public keys associated with the DID:

```
# authorized
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAx3at87jIRB4u/QRIxbuw02ld8O3T/kk3ovCAeSvQFTU=
-----END PUBLIC KEY-----

# authentication
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnNJNI1UymCd3sgxlKkld6bAt2LYu
OCpwJfxVvm0x0P4TZgl5jRxPEl0x88eFP7sM8JPkiHAcaNd4LZ7tfoXJuQ==
-----END PUBLIC KEY-----

# assertion
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDHli2fn+VYADy3mFsu37kwy52bK2
jOIqWnkEKRJ3iKBZRvFK+VC0SEAosa7opBkkj84wl9gQkZhkNcKogSR2OQ==
-----END PUBLIC KEY-----
```

The DID is also registered in the SWIYU Identifier Registry. `didtool` created a DID log for the DID and populated it with a genesis entry. We can fetch the DID log from the Identifier Registry:

```bash
didtool didlog list --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

Output:

```
DID:            did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
Keystore hash:  0e616e6729ad

VERSION-ID                                        VERSION-TIME          DEACTIVATED
1-QmS1MvtTBqk2VYrf5rustBNsoxCfT8BNEvkxDGys8Q75ba  2026-04-30T09:03:20Z  no
```

There is currently only the initial DID log entry for our DID. The line `Keystore hash:  0e616e6729ad` tells us that our `didtool` keystore manages the key pairs for this DID under that hash.

Let's have a closer look at the first DID log entry:

```bash
# show the first entry in the DID log for this DID
didtool didlog entry \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3 \
    --at 1
```

Output:

```
[
  "1-QmS1MvtTBqk2VYrf5rustBNsoxCfT8BNEvkxDGys8Q75ba",
  "2026-04-30T09:03:20Z",
  {
    "method": "did:tdw:0.3",
    "portable": false,
    "scid": "QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj",
    "updateKeys": [
      "z6Mkjn56QsKFDwobVmoDh7RfoAUTHRNRJhkW8HypKcPxz8UD"
    ]
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/jwk/v1"
      ],
      "assertionMethod": [
        "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3#assertion-key-01"
      ],
      "authentication": [
        "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3#authentication-key-01"
      ],
      "id": "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3",
      "verificationMethod": [
        {
          "controller": "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3",
          "id": "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3#authentication-key-01",
          "publicKeyJwk": {
            "crv": "P-256",
            "kid": "authentication-key-01",
            "kty": "EC",
            "x": "ax1-Tav8nyHkibud8NclO9KL_GZihpiyJvwIyh1k1cI",
            "y": "r-Y-EGJ6zzOJdbgUAQqcZGytFFHlO_NB_vkB5j4QlwI"
          },
          "type": "JsonWebKey2020"
        },
        {
          "controller": "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3",
          "id": "did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3#assertion-key-01",
          "publicKeyJwk": {
            "crv": "P-256",
            "kid": "assertion-key-01",
            "kty": "EC",
            "x": "unbIJE5IP3gdU8eFbKSiW1-_7nE0MzeK0Kxt6WxfgjM",
            "y": "a2_Vf07LD9ieehB5pVO9zVp_mW94mQ-yVdNGe-UqqJ4"
          },
          "type": "JsonWebKey2020"
        }
      ]
    }
  },
  [
    {
      "challenge": "1-QmS1MvtTBqk2VYrf5rustBNsoxCfT8BNEvkxDGys8Q75ba",
      "created": "2026-04-30T09:03:20Z",
      "cryptosuite": "eddsa-jcs-2022",
      "proofPurpose": "authentication",
      "proofValue": "z3XxpPQ7ohhZqKSKQSBZmzBaq9M8vESmAxa1sUXeHN68nDLnBdzrQKe5zTrhCxCVH6Zh68gSYmDzU5Vt7cTX3QEy8",
      "type": "DataIntegrityProof",
      "verificationMethod": "did:key:z6Mkjn56QsKFDwobVmoDh7RfoAUTHRNRJhkW8HypKcPxz8UD#z6Mkjn56QsKFDwobVmoDh7RfoAUTHRNRJhkW8HypKcPxz8UD"
    }
  ]
]
```

The three public keys we previously found in the `didtool` keystore are also present in this DID log entry:

* The key with role `authorized` is the one referenced by the proof's `verificationMethod`:

```json
"verificationMethod": "did:key:z6Mkjn56QsKFDwobVmoDh7RfoAUTHRNRJhkW8HypKcPxz8UD#z6Mkjn56QsKFDwobVmoDh7RfoAUTHRNRJhkW8HypKcPxz8UD"
```

* The key with role `authentication`:

```json
"publicKeyJwk": {
  "crv": "P-256",
  "kid": "authentication-key-01",
  "kty": "EC",
  "x": "ax1-Tav8nyHkibud8NclO9KL_GZihpiyJvwIyh1k1cI",
  "y": "r-Y-EGJ6zzOJdbgUAQqcZGytFFHlO_NB_vkB5j4QlwI"
}
```

* The key with role `assertion`:

```json
"publicKeyJwk": {
  "crv": "P-256",
  "kid": "assertion-key-01",
  "kty": "EC",
  "x": "unbIJE5IP3gdU8eFbKSiW1-_7nE0MzeK0Kxt6WxfgjM",
  "y": "a2_Vf07LD9ieehB5pVO9zVp_mW94mQ-yVdNGe-UqqJ4"
}
```

The DID log in the SWIYU Identifier Registry is public. Any verifier who knows our DID can fetch the log and extract the public keys to verify signatures generated with the corresponding private keys.

## Associate the DID with the business partner kacon gmbh

The DID we generated is not yet associated with the business partner kacon gmbh. Neither the DID itself nor the DID's log mentions the name (kacon gmbh) or the **Business Partner ID** (`45ff7b48-446f-11f1-b925-a734ec758462`).

To bind the DID to the business partner kacon gmbh, we have to create an entry in the SWIYU Trust Registry. Currently, there is no such entry:

```bash
# look up the SWIYU trust granted to our DID
didtool trust lookup \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

Output:

```
no trust statements found for did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

There is no API to request an entry in the SWIYU Trust Registry. Currently, you have to send an email like this:

```
To: onboardingbeta@swiyu.admin.ch
Subject: beta Trust Registry Onboarding

Hallo
Ich möchte mich als verifizierte Organisation (Unternehmen, Institution oder Einzelperson) in der beta Trust Infrastructure registrieren.
Hiermit erhalten Sie die erforderlichen Informationen gemäss Onboarding-Dokumentation https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#become-a-trusted-participant
Organisationsname*: <choose one, in my case kacon gmbh>
Bevorzugte Sprache (fr,it,de,rm,en)*: <choose one, in my case de>
Kontaktperson E-Mail*: <choose one>
Beta Base Registry Eintrag (DID in dem Format did:tdw:xx)*: did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3

Mit freundlichen Grüssen
Vorname, Nachname
```

The SWIYU organisation will respond by email within a few business days. After that confirmation, you can verify whether the DID is bound to the business partner. The example below uses a DID that has already been successfully bound to the business partner kacon gmbh:

```bash
# look up whether the DID is bound to a business partner
didtool trust lookup \
    --did did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d
```

Output:

```
Trust statements for did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d

#1  TrustStatementIdentityV1
  issuer:            did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212
  iat (issued at):   2026-04-20T11:12:18Z
  nbf (not before):  2026-01-01T00:00:00Z
  exp (expires):     2027-01-01T00:00:00Z
  entity name:       de-CH: kacon GmbH
  state actor:       no
  status:            SwissTokenStatusList-1.0 idx=643
                     https://status-reg.trust-infra.swiyu-int.admin.ch/api/v1/statuslist/ad94b60b-9efa-4dae-9dd1-4fc33a95bd95.jwt
```

This DID is bound to the business partner kacon gmbh, which isn't a state actor.

How can we be sure this Trust Statement is trustworthy? Is it still valid, or has the issuer revoked it? Did a trustworthy issuer issue the trust statement? Can we validate the signatures? Let's run the verification:

```bash
# verify the trust statement for a DID
didtool trust verify \
    --did did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d
```

Output:

```
Trust statements for did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d
Expected issuer:    did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212

#1  TrustStatementIdentityV1
  iat (issued at):    2026-04-20T11:12:18Z
  iss (issuer):       [ok]   matches expected issuer
  signature:          [ok]   valid (kid: did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212#assert-key-02)
  freshness:          [ok]   now within nbf..exp (2026-01-01T00:00:00Z..2027-01-01T00:00:00Z)
  status:             [ok]   valid (idx=643, bits=2)
  entity name:        de-CH: kacon GmbH
  state actor:        no
  verdict:            [ok]    trusted
```

The output confirms that the trust statement was issued by the expected SWIYU issuer, is still valid (within `nbf..exp` and not revoked), and the signatures check out.

## Using `didtool` to manage a DID

During the lifecycle of a DID you may need to update one or all of its key pairs (key rotation). At the end of the lifecycle the DID can be deactivated.

### Rotating key pairs associated with a DID

To rotate all three key pairs at once:

```bash
# rotate the key pairs
didtool did rotate \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3 \
    --role all
```

There are now two sets of key pairs for this DID in the `didtool` keystore:

```bash
didtool key versions \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

Output:

```
1  initial
2  authorized authentication assertion
```

The output tells us that all three key pairs were rotated in the second version.

The DID log now includes two entries:

```bash
# list the DID log entries for this DID
didtool didlog list \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

Output:

```
DID:            did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
Keystore hash:  0e616e6729ad

VERSION-ID                                        VERSION-TIME          DEACTIVATED
1-QmS1MvtTBqk2VYrf5rustBNsoxCfT8BNEvkxDGys8Q75ba  2026-04-30T09:03:20Z  no
2-QmUrsLBAyDqvxiDnjsHS81Y2RDeEFczEMryk9QXpG5Tq4R  2026-04-30T10:14:52Z  no
```

### Deactivating a DID

A DID can be deactivated when it is no longer in use. The DID log still exists in the Identifier Registry, but a final entry marks the DID as deactivated.

```bash
# deactivate the DID
didtool did deactivate \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

After running this, list the DID log to confirm the deactivation:

```bash
didtool didlog list \
    --did did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
```

Output:

```
DID:            did:tdw:QmUmKYAuBJvaYqC1TgNyo9ZuoMiUVBmV2dyADTUiHMSpGj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:468c4af1-7af1-40ad-a6a5-a0076a8f51e3
Keystore hash:  0e616e6729ad

VERSION-ID                                        VERSION-TIME          DEACTIVATED
1-QmS1MvtTBqk2VYrf5rustBNsoxCfT8BNEvkxDGys8Q75ba  2026-04-30T09:03:20Z  no
2-QmUrsLBAyDqvxiDnjsHS81Y2RDeEFczEMryk9QXpG5Tq4R  2026-04-30T10:14:52Z  no
3-QmR43xvFMeQ3phaDsrES37wRR115avSoR5gNPQMsDixmx8  2026-04-30T10:39:08Z  yes
```

The third entry shows `DEACTIVATED  yes`, confirming the DID is deactivated.

[swiyu-onboarding]: https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/
[agov]: https://www.agov.admin.ch/de
[ePortal]: https://eportal.admin.ch/
