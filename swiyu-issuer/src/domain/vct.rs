/// One supported credential type.
///
/// `vct` is the SD-JWT VC type identifier (a URI). `schema` is the
/// raw JSON Schema document the management API uses to validate
/// claims at credential-offer creation time. Bundled at compile
/// time via `include_str!`; the schema files live under `schemas/`.
pub struct VctEntry {
    pub vct: &'static str,
    pub schema: &'static str,
}

/// Single source of truth for the credential types this issuer
/// supports. The management API compiles the schemas into JSON
/// Schema validators; the OIDC metadata document advertises the
/// `vct` list in `credential_configurations_supported`. Adding a
/// VCT is a one-place edit.
pub const CATALOGUE: &[VctEntry] = &[VctEntry {
    vct: "urn:communal:local-residence-id",
    schema: include_str!("../../schemas/urn_communal_local-residence-id.json"),
}];
