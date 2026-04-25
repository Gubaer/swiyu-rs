use std::fmt;
use std::str::FromStr;

/// A DID (Decentralized Identifier) according to the [did:tdw v0.3][did-tdw-v0-3] specification,
/// as used in the Swiss Trust Infrastructure for the Swiss E-ID.
///
/// [did-tdw-v0-3]: https://identity.foundation/didwebvh/v0.3/
#[derive(Debug, Clone, PartialEq)]
pub struct DID {
    /// The Self-Certifying Identifier (SCID) component of the DID, if present.
    scid: Option<String>,
    /// The domain component of the DID.
    domain: String,
    /// The optional path component, as a `:`-separated list of path segments.
    path: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum DIDError {
    MissingPrefix,
    MissingSCID,
    MissingDomain,
    InvalidDomain,
    InvalidPath,
}

impl fmt::Display for DIDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DIDError::MissingPrefix => write!(f, "DID must start with 'did:tdw:'"),
            DIDError::MissingSCID => write!(f, "DID is missing the SCID component"),
            DIDError::MissingDomain => write!(f, "DID is missing the domain component"),
            DIDError::InvalidDomain => {
                write!(
                    f,
                    "domain must be a '.'-separated sequence of non-empty segments"
                )
            }
            DIDError::InvalidPath => {
                write!(f, "path must be a ':'-separated list of non-empty segments")
            }
        }
    }
}

impl std::error::Error for DIDError {}

pub type DIDResult<T> = Result<T, DIDError>;

fn is_valid_domain(domain: &str) -> bool {
    !domain.is_empty() && domain.split('.').all(|seg| !seg.is_empty())
}

fn is_valid_path(path: &str) -> bool {
    !path.is_empty() && path.split(':').all(|seg| !seg.is_empty())
}

impl DID {
    pub fn try_new(scid: Option<String>, domain: String, path: Option<String>) -> DIDResult<Self> {
        if !is_valid_domain(&domain) {
            return Err(DIDError::InvalidDomain);
        }
        if let Some(ref p) = path
            && !is_valid_path(p)
        {
            return Err(DIDError::InvalidPath);
        }
        Ok(Self { scid, domain, path })
    }

    pub fn parse(did: &str) -> DIDResult<Self> {
        let rest = did
            .strip_prefix("did:tdw:")
            .ok_or(DIDError::MissingPrefix)?;

        // Format after stripping prefix: {SCID}:{domain}[:{path_segments}]
        // splitn(3) keeps the full path (including any embedded colons) in the third slot.
        let mut parts = rest.splitn(3, ':');

        let scid_raw = parts.next().ok_or(DIDError::MissingSCID)?;
        let scid = if scid_raw.is_empty() {
            None
        } else {
            Some(scid_raw.to_string())
        };

        let domain_str = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(DIDError::MissingDomain)?;

        if !is_valid_domain(domain_str) {
            return Err(DIDError::InvalidDomain);
        }

        let path = match parts.next() {
            Some(p) if !is_valid_path(p) => return Err(DIDError::InvalidPath),
            Some(p) => Some(p.to_string()),
            None => None,
        };

        Ok(Self {
            scid,
            domain: domain_str.to_string(),
            path,
        })
    }

    pub fn scid(&self) -> Option<&str> {
        self.scid.as_deref()
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl fmt::Display for DID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scid = self.scid.as_deref().unwrap_or("{SCID}");
        write!(f, "did:tdw:{scid}:{}", self.domain)?;
        if let Some(path) = &self.path {
            write!(f, ":{path}")?;
        }
        Ok(())
    }
}

impl FromStr for DID {
    type Err = DIDError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DID::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let did = DID::parse("did:tdw:abc123:example.com").unwrap();
        assert_eq!(did.scid(), Some("abc123"));
        assert_eq!(did.domain(), "example.com");
        assert_eq!(did.path(), None);
    }

    #[test]
    fn parse_with_path() {
        let did = DID::parse("did:tdw:abc123:example.com:dids:issuer").unwrap();
        assert_eq!(did.scid(), Some("abc123"));
        assert_eq!(did.domain(), "example.com");
        assert_eq!(did.path(), Some("dids:issuer"));
    }

    #[test]
    fn parse_with_encoded_port() {
        // Ports are percent-encoded in the domain segment per the did:tdw spec.
        let did = DID::parse("did:tdw:abc123:example.com%3A3000:path").unwrap();
        assert_eq!(did.domain(), "example.com%3A3000");
        assert_eq!(did.path(), Some("path"));
    }

    #[test]
    fn parse_wrong_method() {
        assert_eq!(
            DID::parse("did:web:example.com").unwrap_err(),
            DIDError::MissingPrefix
        );
    }

    #[test]
    fn parse_missing_domain() {
        assert_eq!(
            DID::parse("did:tdw:abc123").unwrap_err(),
            DIDError::MissingDomain
        );
    }

    #[test]
    fn parse_invalid_domain_empty_segment() {
        assert_eq!(
            DID::parse("did:tdw:abc123:example..com").unwrap_err(),
            DIDError::InvalidDomain
        );
    }

    #[test]
    fn parse_invalid_domain_trailing_dot() {
        assert_eq!(
            DID::parse("did:tdw:abc123:example.com.").unwrap_err(),
            DIDError::InvalidDomain
        );
    }

    #[test]
    fn parse_invalid_path_empty_segment() {
        assert_eq!(
            DID::parse("did:tdw:abc123:example.com:dids::issuer").unwrap_err(),
            DIDError::InvalidPath
        );
    }

    #[test]
    fn new_valid() {
        let did = DID::try_new(Some("abc".into()), "example.com".into(), None).unwrap();
        assert_eq!(did.to_string(), "did:tdw:abc:example.com");
    }

    #[test]
    fn new_invalid_domain() {
        assert_eq!(
            DID::try_new(None, "example..com".into(), None).unwrap_err(),
            DIDError::InvalidDomain
        );
    }

    #[test]
    fn new_invalid_path() {
        assert_eq!(
            DID::try_new(None, "example.com".into(), Some(":bad".into())).unwrap_err(),
            DIDError::InvalidPath
        );
    }

    #[test]
    fn display_roundtrip() {
        for s in [
            "did:tdw:abc123:example.com",
            "did:tdw:abc123:example.com:dids:issuer",
            "did:tdw:abc123:example.com%3A3000:path",
        ] {
            assert_eq!(DID::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn from_str() {
        let did: DID = "did:tdw:abc123:example.com".parse().unwrap();
        assert_eq!(did.domain(), "example.com");
    }
}
