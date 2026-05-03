/// The role a key pair plays for a DID-based issuer.
///
/// Every issuer holds three private keys, one per role.
///
/// - `Authorized` — signs DID log entries (e.g. the
///   `DataIntegrityStatement` for `did:tdw` / `did:webvh`).
/// - `Authentication` — its public key is embedded in DID log entries
///   for the DID's `authentication` verification relationship.
/// - `Assertion` — signs verifiable credentials issued by the DID
///   (corresponds to the `assertionMethod` verification relationship).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    Authorized,
    Authentication,
    Assertion,
}
