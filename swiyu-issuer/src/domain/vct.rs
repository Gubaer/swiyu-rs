/// One supported credential type.
pub struct VctEntry {
    /// SD-JWT VC type identifier (a URI).
    pub vct: &'static str,
    /// Raw JSON Schema document used to validate claims at credential-offer
    /// creation time. Bundled at compile time via `include_str!`.
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
