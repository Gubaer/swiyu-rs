pub mod public_keys;
pub use public_keys::{KeyUse, PublicKey, PublicKeyJWK, PublicKeyMultibase};

use serde_json::{Map, Value, json};
use std::fmt;

pub type DIDDocResult<T> = Result<T, DIDDocError>;

#[derive(Debug, PartialEq)]
pub enum DIDDocError {
    MissingField(String),
    InvalidFieldType(String),
    InvalidFormat(String),
}

impl fmt::Display for DIDDocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DIDDocError::MissingField(field) => write!(f, "missing required field: {field}"),
            DIDDocError::InvalidFieldType(msg) => write!(f, "invalid field type: {msg}"),
            DIDDocError::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
        }
    }
}

impl std::error::Error for DIDDocError {}

/// A cryptographic key or other mechanism used to authenticate or prove control of a DID subject.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationMethod {
    /// DID URL identifying this verification method.
    id: String,
    /// The cryptographic suite type (e.g. "JsonWebKey2020", "Ed25519VerificationKey2020").
    type_: String,
    /// DID of the entity that controls this key.
    controller: String,
    /// The public key material. Required here because did:tdw always embeds key material
    /// directly in the verification method rather than referencing it externally.
    public_key: PublicKey,
}

impl VerificationMethod {
    pub fn new(id: String, type_: String, controller: String, public_key: PublicKey) -> Self {
        Self {
            id,
            type_,
            controller,
            public_key,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn type_(&self) -> &str {
        &self.type_
    }

    pub fn controller(&self) -> &str {
        &self.controller
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// A verification method that is either embedded inline or referenced by DID URL.
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationMethodOrRef {
    Embedded(Box<VerificationMethod>),
    /// A DID URL pointing to a verification method declared elsewhere in the document.
    Reference(String),
}

/// A network endpoint through which the DID subject can be reached or interacted with.
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    /// URI identifying the service.
    id: String,
    /// One or more service type strings (e.g. "LinkedDomains", "DIDCommMessaging").
    type_: Vec<String>,
    /// The endpoint URI(s) or map(s) where the service operates.
    service_endpoint: Value,
}

impl Service {
    pub fn new(id: String, type_: Vec<String>, service_endpoint: Value) -> Self {
        Self {
            id,
            type_,
            service_endpoint,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn type_(&self) -> &[String] {
        &self.type_
    }

    pub fn service_endpoint(&self) -> &Value {
        &self.service_endpoint
    }
}

/// A DID Document as defined by the W3C DID 1.0 data model.
#[derive(Debug, Clone, PartialEq)]
pub struct DIDDoc {
    /// The DID that identifies this document's subject. Required.
    id: String,
    /// Alternative URIs or DIDs by which the subject is also known.
    also_known_as: Vec<String>,
    /// DIDs of entities authorized to update this document.
    controller: Vec<String>,
    /// Cryptographic verification methods associated with the subject.
    verification_method: Vec<VerificationMethod>,
    /// Methods usable for authenticating as the DID subject.
    authentication: Vec<VerificationMethodOrRef>,
    /// Methods usable for expressing claims (e.g. issuing verifiable credentials).
    assertion_method: Vec<VerificationMethodOrRef>,
    /// Methods usable for key agreement (encrypted communication).
    key_agreement: Vec<VerificationMethodOrRef>,
    /// Methods usable for invoking a cryptographic capability.
    capability_invocation: Vec<VerificationMethodOrRef>,
    /// Methods usable for delegating a cryptographic capability.
    capability_delegation: Vec<VerificationMethodOrRef>,
    /// Service endpoints for interacting with the DID subject.
    service: Vec<Service>,
}

impl DIDDoc {
    /// Creates a minimal DIDDoc with the given `id` and all optional fields empty.
    pub fn new(id: String) -> Self {
        Self {
            id,
            also_known_as: Vec::new(),
            controller: Vec::new(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
        }
    }

    /// Parses a DIDDoc from an already-parsed JSON-LD value.
    ///
    /// Expects the JSON-LD representation described in
    /// <https://www.w3.org/TR/did-1.0/#consumption-0>.
    pub fn try_from_jsonld(v: &Value) -> DIDDocResult<Self> {
        let obj = v.as_object().ok_or_else(|| {
            DIDDocError::InvalidFormat("DID document must be a JSON object".into())
        })?;

        if obj.get("@context").is_none() {
            return Err(DIDDocError::MissingField("@context".into()));
        }

        let id = required_string(obj, "id")?;
        let also_known_as = string_or_array(obj, "alsoKnownAs")?;
        let controller = string_or_array(obj, "controller")?;
        let verification_method = parse_vm_array(obj, "verificationMethod")?;
        let authentication = parse_vm_or_ref_array(obj, "authentication")?;
        let assertion_method = parse_vm_or_ref_array(obj, "assertionMethod")?;
        let key_agreement = parse_vm_or_ref_array(obj, "keyAgreement")?;
        let capability_invocation = parse_vm_or_ref_array(obj, "capabilityInvocation")?;
        let capability_delegation = parse_vm_or_ref_array(obj, "capabilityDelegation")?;
        let service = parse_service_array(obj, "service")?;

        Ok(Self {
            id,
            also_known_as,
            controller,
            verification_method,
            authentication,
            assertion_method,
            key_agreement,
            capability_invocation,
            capability_delegation,
            service,
        })
    }

    /// Serializes this DIDDoc to JSON-LD as described in
    /// <https://www.w3.org/TR/did-1.0/#production-0>.
    pub fn to_jsonld(&self) -> Value {
        let mut map = Map::new();

        map.insert("@context".into(), json!(["https://www.w3.org/ns/did/v1"]));
        map.insert("id".into(), json!(self.id));

        if !self.also_known_as.is_empty() {
            map.insert("alsoKnownAs".into(), json!(self.also_known_as));
        }
        if !self.controller.is_empty() {
            map.insert("controller".into(), string_or_array_value(&self.controller));
        }
        if !self.verification_method.is_empty() {
            let vms: Vec<Value> = self.verification_method.iter().map(vm_to_json).collect();
            map.insert("verificationMethod".into(), json!(vms));
        }
        if !self.authentication.is_empty() {
            map.insert(
                "authentication".into(),
                json!(
                    self.authentication
                        .iter()
                        .map(vm_or_ref_to_json)
                        .collect::<Vec<_>>()
                ),
            );
        }
        if !self.assertion_method.is_empty() {
            map.insert(
                "assertionMethod".into(),
                json!(
                    self.assertion_method
                        .iter()
                        .map(vm_or_ref_to_json)
                        .collect::<Vec<_>>()
                ),
            );
        }
        if !self.key_agreement.is_empty() {
            map.insert(
                "keyAgreement".into(),
                json!(
                    self.key_agreement
                        .iter()
                        .map(vm_or_ref_to_json)
                        .collect::<Vec<_>>()
                ),
            );
        }
        if !self.capability_invocation.is_empty() {
            map.insert(
                "capabilityInvocation".into(),
                json!(
                    self.capability_invocation
                        .iter()
                        .map(vm_or_ref_to_json)
                        .collect::<Vec<_>>()
                ),
            );
        }
        if !self.capability_delegation.is_empty() {
            map.insert(
                "capabilityDelegation".into(),
                json!(
                    self.capability_delegation
                        .iter()
                        .map(vm_or_ref_to_json)
                        .collect::<Vec<_>>()
                ),
            );
        }
        if !self.service.is_empty() {
            let services: Vec<Value> = self.service.iter().map(service_to_json).collect();
            map.insert("service".into(), json!(services));
        }

        Value::Object(map)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn also_known_as(&self) -> &[String] {
        &self.also_known_as
    }

    pub fn controller(&self) -> &[String] {
        &self.controller
    }

    pub fn verification_method(&self) -> &[VerificationMethod] {
        &self.verification_method
    }

    pub fn authentication(&self) -> &[VerificationMethodOrRef] {
        &self.authentication
    }

    pub fn assertion_method(&self) -> &[VerificationMethodOrRef] {
        &self.assertion_method
    }

    pub fn key_agreement(&self) -> &[VerificationMethodOrRef] {
        &self.key_agreement
    }

    pub fn capability_invocation(&self) -> &[VerificationMethodOrRef] {
        &self.capability_invocation
    }

    pub fn capability_delegation(&self) -> &[VerificationMethodOrRef] {
        &self.capability_delegation
    }

    pub fn service(&self) -> &[Service] {
        &self.service
    }
}

// --- serialization helpers ---

fn vm_to_json(vm: &VerificationMethod) -> Value {
    let mut map = Map::new();
    map.insert("id".into(), json!(vm.id));
    map.insert("type".into(), json!(vm.type_));
    map.insert("controller".into(), json!(vm.controller));
    match &vm.public_key {
        PublicKey::Jwk(jwk) => {
            map.insert("publicKeyJwk".into(), jwk.to_json());
        }
        PublicKey::Multibase(mb) => {
            map.insert("publicKeyMultibase".into(), json!(mb.to_string()));
        }
    }
    Value::Object(map)
}

fn vm_or_ref_to_json(v: &VerificationMethodOrRef) -> Value {
    match v {
        VerificationMethodOrRef::Embedded(vm) => vm_to_json(vm),
        VerificationMethodOrRef::Reference(s) => json!(s),
    }
}

fn service_to_json(s: &Service) -> Value {
    let type_value = if s.type_.len() == 1 {
        json!(s.type_[0])
    } else {
        json!(s.type_)
    };
    json!({
        "id": s.id,
        "type": type_value,
        "serviceEndpoint": s.service_endpoint,
    })
}

// Serialize a list as a bare string when it has one element, array otherwise.
// Used for `controller` which the spec allows as string or set.
fn string_or_array_value(values: &[String]) -> Value {
    if values.len() == 1 {
        json!(values[0])
    } else {
        json!(values)
    }
}

// --- parsing helpers ---
// pub(super) so that public_keys.rs can call them without duplicating the logic.

pub(super) fn required_string(obj: &Map<String, Value>, key: &str) -> DIDDocResult<String> {
    obj.get(key)
        .ok_or_else(|| DIDDocError::MissingField(key.into()))?
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| DIDDocError::InvalidFieldType(format!("'{key}' must be a string")))
}

pub(super) fn optional_string(obj: &Map<String, Value>, key: &str) -> DIDDocResult<Option<String>> {
    match obj.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| DIDDocError::InvalidFieldType(format!("'{key}' must be a string"))),
    }
}

pub(super) fn optional_string_array(
    obj: &Map<String, Value>,
    key: &str,
) -> DIDDocResult<Option<Vec<String>>> {
    let arr = match obj.get(key) {
        None => return Ok(None),
        Some(v) => v
            .as_array()
            .ok_or_else(|| DIDDocError::InvalidFieldType(format!("'{key}' must be an array")))?,
    };
    let strings = arr
        .iter()
        .map(|v| {
            v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                DIDDocError::InvalidFieldType(format!("'{key}' elements must be strings"))
            })
        })
        .collect::<DIDDocResult<Vec<_>>>()?;
    Ok(Some(strings))
}

// Accepts a string or an array of strings; always returns Vec.
fn string_or_array(obj: &Map<String, Value>, key: &str) -> DIDDocResult<Vec<String>> {
    match obj.get(key) {
        None => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    DIDDocError::InvalidFieldType(format!("'{key}' elements must be strings"))
                })
            })
            .collect(),
        Some(_) => Err(DIDDocError::InvalidFieldType(format!(
            "'{key}' must be a string or array of strings"
        ))),
    }
}

fn parse_vm_array(obj: &Map<String, Value>, key: &str) -> DIDDocResult<Vec<VerificationMethod>> {
    let arr = match obj.get(key) {
        None => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| DIDDocError::InvalidFieldType(format!("'{key}' must be an array")))?,
    };
    arr.iter().map(vm_from_json).collect()
}

fn parse_vm_or_ref_array(
    obj: &Map<String, Value>,
    key: &str,
) -> DIDDocResult<Vec<VerificationMethodOrRef>> {
    let arr = match obj.get(key) {
        None => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| DIDDocError::InvalidFieldType(format!("'{key}' must be an array")))?,
    };
    arr.iter().map(vm_or_ref_from_json).collect()
}

fn parse_service_array(obj: &Map<String, Value>, key: &str) -> DIDDocResult<Vec<Service>> {
    let arr = match obj.get(key) {
        None => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| DIDDocError::InvalidFieldType(format!("'{key}' must be an array")))?,
    };
    arr.iter().map(service_from_json).collect()
}

fn vm_from_json(v: &Value) -> DIDDocResult<VerificationMethod> {
    let obj = v.as_object().ok_or_else(|| {
        DIDDocError::InvalidFieldType("verification method must be an object".into())
    })?;
    let id = required_string(obj, "id")?;
    let type_ = required_string(obj, "type")?;
    let controller = required_string(obj, "controller")?;
    let public_key = if let Some(jwk) = obj.get("publicKeyJwk") {
        PublicKey::Jwk(Box::new(PublicKeyJWK::try_from_json(jwk)?))
    } else if let Some(mb) = obj.get("publicKeyMultibase").and_then(|v| v.as_str()) {
        PublicKey::Multibase(PublicKeyMultibase::try_from_string(mb)?)
    } else {
        return Err(DIDDocError::MissingField(
            "verification method must have 'publicKeyJwk' or 'publicKeyMultibase'".into(),
        ));
    };
    Ok(VerificationMethod {
        id,
        type_,
        controller,
        public_key,
    })
}

fn vm_or_ref_from_json(v: &Value) -> DIDDocResult<VerificationMethodOrRef> {
    if let Some(s) = v.as_str() {
        Ok(VerificationMethodOrRef::Reference(s.to_string()))
    } else {
        Ok(VerificationMethodOrRef::Embedded(Box::new(vm_from_json(
            v,
        )?)))
    }
}

fn service_from_json(v: &Value) -> DIDDocResult<Service> {
    let obj = v
        .as_object()
        .ok_or_else(|| DIDDocError::InvalidFieldType("service must be an object".into()))?;
    let id = required_string(obj, "id")?;
    let type_ = match obj.get("type") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    DIDDocError::InvalidFieldType("service 'type' elements must be strings".into())
                })
            })
            .collect::<DIDDocResult<Vec<_>>>()?,
        Some(_) => {
            return Err(DIDDocError::InvalidFieldType(
                "service 'type' must be a string or array of strings".into(),
            ));
        }
        None => return Err(DIDDocError::MissingField("service 'type'".into())),
    };
    let service_endpoint = obj
        .get("serviceEndpoint")
        .cloned()
        .ok_or_else(|| DIDDocError::MissingField("serviceEndpoint".into()))?;
    Ok(Service {
        id,
        type_,
        service_endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_doc_json() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:abc123:example.com",
            "alsoKnownAs": ["https://example.com/user/alice"],
            "controller": "did:tdw:abc123:example.com",
            "verificationMethod": [{
                "id": "did:tdw:abc123:example.com#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:tdw:abc123:example.com",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                }
            }],
            "authentication": [
                "did:tdw:abc123:example.com#key-1",
                {
                    "id": "did:tdw:abc123:example.com#key-2",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:tdw:abc123:example.com",
                    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }
            ],
            "service": [{
                "id": "did:tdw:abc123:example.com#linked-domain",
                "type": "LinkedDomains",
                "serviceEndpoint": "https://example.com"
            }]
        })
    }

    #[test]
    fn parse_full_doc() {
        let doc = DIDDoc::try_from_jsonld(&sample_doc_json()).unwrap();
        assert_eq!(doc.id(), "did:tdw:abc123:example.com");
        assert_eq!(doc.also_known_as(), &["https://example.com/user/alice"]);
        assert_eq!(doc.controller(), &["did:tdw:abc123:example.com"]);
        assert_eq!(doc.verification_method().len(), 1);
        assert_eq!(doc.authentication().len(), 2);
        assert_eq!(doc.service().len(), 1);
    }

    #[test]
    fn parse_verification_method_jwk() {
        let doc = DIDDoc::try_from_jsonld(&sample_doc_json()).unwrap();
        let vm = &doc.verification_method()[0];
        assert_eq!(vm.id(), "did:tdw:abc123:example.com#key-1");
        assert_eq!(vm.type_(), "JsonWebKey2020");
        assert_eq!(vm.controller(), "did:tdw:abc123:example.com");
        let PublicKey::Jwk(jwk) = vm.public_key() else {
            panic!("expected Jwk");
        };
        assert_eq!(jwk.kty(), "OKP");
        assert_eq!(jwk.crv(), Some("Ed25519"));
        assert!(jwk.x().is_some());
    }

    #[test]
    fn parse_verification_method_multibase() {
        let doc = DIDDoc::try_from_jsonld(&sample_doc_json()).unwrap();
        let VerificationMethodOrRef::Embedded(vm) = &doc.authentication()[1] else {
            panic!("expected embedded");
        };
        let PublicKey::Multibase(mb) = vm.public_key() else {
            panic!("expected Multibase");
        };
        assert!(!mb.raw_key().is_empty());
        assert!(mb.to_string().starts_with('z'));
    }

    #[test]
    fn parse_authentication_ref_and_embedded() {
        let doc = DIDDoc::try_from_jsonld(&sample_doc_json()).unwrap();
        assert!(matches!(
            &doc.authentication()[0],
            VerificationMethodOrRef::Reference(s) if s == "did:tdw:abc123:example.com#key-1"
        ));
        assert!(matches!(
            &doc.authentication()[1],
            VerificationMethodOrRef::Embedded(_)
        ));
    }

    #[test]
    fn parse_service() {
        let doc = DIDDoc::try_from_jsonld(&sample_doc_json()).unwrap();
        let svc = &doc.service()[0];
        assert_eq!(svc.id(), "did:tdw:abc123:example.com#linked-domain");
        assert_eq!(svc.type_(), &["LinkedDomains"]);
    }

    #[test]
    fn missing_context() {
        let v = json!({ "id": "did:tdw:abc:example.com" });
        assert!(matches!(
            DIDDoc::try_from_jsonld(&v).unwrap_err(),
            DIDDocError::MissingField(_)
        ));
    }

    #[test]
    fn missing_id() {
        let v = json!({ "@context": ["https://www.w3.org/ns/did/v1"] });
        assert!(matches!(
            DIDDoc::try_from_jsonld(&v).unwrap_err(),
            DIDDocError::MissingField(_)
        ));
    }

    #[test]
    fn roundtrip_to_jsonld() {
        let original = sample_doc_json();
        let doc = DIDDoc::try_from_jsonld(&original).unwrap();
        let produced = doc.to_jsonld();
        // Round-trip: re-parse the produced JSON-LD and compare the data model.
        let doc2 = DIDDoc::try_from_jsonld(&produced).unwrap();
        assert_eq!(doc, doc2);
    }

    #[test]
    fn new_constructor() {
        let doc = DIDDoc::new("did:tdw:abc:example.com".into());
        assert_eq!(doc.id(), "did:tdw:abc:example.com");
        assert!(doc.service().is_empty());
        let v = doc.to_jsonld();
        assert_eq!(v["id"], "did:tdw:abc:example.com");
        assert!(v.get("service").is_none());
    }
}
