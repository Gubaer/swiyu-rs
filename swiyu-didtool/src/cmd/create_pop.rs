use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer as _;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::json;

use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;

use crate::cmd::{ResolveError, resolve_entry};
use crate::keystore::{KeyRole, KeyStore, KeyStoreEntry, KeyStoreError};

pub struct CreatePopArgs {
    pub did: String,
    pub role: KeyRole,
    pub nonce: Option<String>,
    pub ttl: u64,
    pub version: Option<u32>,
    pub out: Option<PathBuf>,
    pub force: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CreatePopError {
    #[error("--ttl must be a positive integer")]
    InvalidTtl,
    #[error("--force is only meaningful with --out")]
    ForceWithoutOut,
    #[error("file '{}' already exists; pass --force to overwrite", path.display())]
    FileExists { path: PathBuf },
    #[error("cannot write '{}': {source}", path.display())]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write to stdout: {0}")]
    WriteStdout(std::io::Error),
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
}

pub fn cmd_create_pop(store: &KeyStore, args: CreatePopArgs) -> Result<(), CreatePopError> {
    if args.ttl == 0 {
        return Err(CreatePopError::InvalidTtl);
    }
    if args.force && args.out.is_none() {
        return Err(CreatePopError::ForceWithoutOut);
    }

    let entry = resolve_entry(store, &args.did)?;
    let did = entry.did().to_string();

    let (kid, signer) = resolve_role(&entry, args.role, args.version)?;
    let alg = signer.alg();

    let nonce = match args.nonce {
        Some(n) => n,
        None => {
            let n = generate_nonce();
            eprintln!("generated nonce: {n}");
            n
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now + args.ttl;

    let header = json!({ "alg": alg, "kid": kid });
    let payload = json!({
        "iss": did,
        "iat": now,
        "exp": exp,
        "nonce": nonce,
    });

    let header_bytes = serde_json::to_vec(&header).expect("header is serialisable");
    let payload_bytes = serde_json::to_vec(&payload).expect("payload is serialisable");
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_bytes);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = signer.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);
    let jwt = format!("{signing_input}.{signature_b64}");

    write_output(&jwt, args.out.as_deref(), args.force)?;
    Ok(())
}

enum Signer {
    Eddsa(ed25519_dalek::SigningKey),
    Ecdsa(p256::ecdsa::SigningKey),
}

impl Signer {
    fn alg(&self) -> &'static str {
        match self {
            Self::Eddsa(_) => "EdDSA",
            Self::Ecdsa(_) => "ES256",
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::Eddsa(k) => k.sign(msg).to_bytes().to_vec(),
            Self::Ecdsa(k) => {
                let sig: p256::ecdsa::Signature = k.sign(msg);
                sig.to_bytes().to_vec()
            }
        }
    }
}

fn resolve_role(
    entry: &KeyStoreEntry,
    role: KeyRole,
    version: Option<u32>,
) -> Result<(String, Signer), CreatePopError> {
    match role {
        KeyRole::Authorized => {
            let signing_key = entry.load_eddsa(role, version)?;
            let pub_bytes = signing_key.verifying_key().to_bytes();
            let multikey = ed25519_verifying_key_to_multikey(&pub_bytes);
            let kid = format!("did:key:{multikey}#{multikey}");
            Ok((kid, Signer::Eddsa(signing_key)))
        }
        KeyRole::Authentication => {
            let signing_key = entry.load_ecdsa(role, version)?;
            let kid = format!("{}#authentication-key-01", entry.did());
            Ok((kid, Signer::Ecdsa(signing_key)))
        }
        KeyRole::Assertion => {
            let signing_key = entry.load_ecdsa(role, version)?;
            let kid = format!("{}#assertion-key-01", entry.did());
            Ok((kid, Signer::Ecdsa(signing_key)))
        }
    }
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn write_output(jwt: &str, out: Option<&Path>, force: bool) -> Result<(), CreatePopError> {
    match out {
        Some(path) => {
            if path.exists() && !force {
                return Err(CreatePopError::FileExists {
                    path: path.to_path_buf(),
                });
            }
            std::fs::write(path, jwt.as_bytes()).map_err(|source| CreatePopError::WriteOutput {
                path: path.to_path_buf(),
                source,
            })
        }
        None => std::io::stdout()
            .write_all(jwt.as_bytes())
            .map_err(CreatePopError::WriteStdout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;
    use swiyu_core::did::DID;

    fn test_did() -> DID {
        DID::parse("did:webvh:abc123:example.com").unwrap()
    }

    fn make_store() -> (tempfile::TempDir, KeyStore, KeyStoreEntry) {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open_or_create(dir.path()).unwrap();
        let entry = store
            .commit(KeyStore::generate().unwrap(), &test_did())
            .unwrap();
        (dir, store, entry)
    }

    fn run_to_file(
        store: &KeyStore,
        entry: &KeyStoreEntry,
        role: KeyRole,
        nonce: Option<&str>,
        ttl: u64,
    ) -> (tempfile::TempDir, PathBuf, String) {
        let outdir = tempfile::tempdir().unwrap();
        let path = outdir.path().join("pop.jwt");
        cmd_create_pop(
            store,
            CreatePopArgs {
                did: entry.hash().to_string(),
                role,
                nonce: nonce.map(String::from),
                ttl,
                version: None,
                out: Some(path.clone()),
                force: false,
            },
        )
        .unwrap();
        let jwt = std::fs::read_to_string(&path).unwrap();
        (outdir, path, jwt)
    }

    fn split(jwt: &str) -> (String, String, Vec<u8>) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "expected 3 JWT parts");
        let header_json = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let payload_json = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        (header_json, payload_json, signature)
    }

    #[test]
    fn ed25519_roundtrip_authorized_role() {
        let (_dir, store, entry) = make_store();
        let (_outdir, _path, jwt) =
            run_to_file(&store, &entry, KeyRole::Authorized, Some("n1"), 60);
        let (header_json, payload_json, signature) = split(&jwt);
        let header: serde_json::Value = serde_json::from_str(&header_json).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();

        assert_eq!(header["alg"], "EdDSA");
        assert!(header["kid"].as_str().unwrap().starts_with("did:key:z6Mk"));
        assert_eq!(payload["iss"], test_did().to_string());
        assert_eq!(payload["nonce"], "n1");
        assert_eq!(
            payload["exp"].as_u64().unwrap(),
            payload["iat"].as_u64().unwrap() + 60
        );

        let signing_input = jwt.rsplit_once('.').unwrap().0;
        let signing_key = entry.load_eddsa(KeyRole::Authorized, None).unwrap();
        let verifying_key = signing_key.verifying_key();
        let sig_bytes: [u8; 64] = signature.try_into().expect("ed25519 sig is 64 bytes");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[test]
    fn p256_roundtrip_assertion_role() {
        let (_dir, store, entry) = make_store();
        let (_outdir, _path, jwt) = run_to_file(&store, &entry, KeyRole::Assertion, Some("n2"), 30);
        let (header_json, payload_json, signature) = split(&jwt);
        let header: serde_json::Value = serde_json::from_str(&header_json).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], format!("{}#assertion-key-01", test_did()));
        assert_eq!(payload["nonce"], "n2");

        let signing_input = jwt.rsplit_once('.').unwrap().0;
        let signing_key = entry.load_ecdsa(KeyRole::Assertion, None).unwrap();
        let verifying_key = *signing_key.verifying_key();
        let sig = p256::ecdsa::Signature::from_slice(&signature).unwrap();
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[test]
    fn p256_authentication_role_kid_shape() {
        let (_dir, store, entry) = make_store();
        let (_outdir, _path, jwt) =
            run_to_file(&store, &entry, KeyRole::Authentication, Some("n3"), 30);
        let (header_json, _, _) = split(&jwt);
        let header: serde_json::Value = serde_json::from_str(&header_json).unwrap();
        assert_eq!(
            header["kid"],
            format!("{}#authentication-key-01", test_did())
        );
        assert_eq!(header["alg"], "ES256");
    }

    #[test]
    fn ttl_zero_is_rejected() {
        let (_dir, store, entry) = make_store();
        let err = cmd_create_pop(
            &store,
            CreatePopArgs {
                did: entry.hash().to_string(),
                role: KeyRole::Assertion,
                nonce: Some("x".into()),
                ttl: 0,
                version: None,
                out: None,
                force: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CreatePopError::InvalidTtl));
    }

    #[test]
    fn force_without_out_is_rejected() {
        let (_dir, store, entry) = make_store();
        let err = cmd_create_pop(
            &store,
            CreatePopArgs {
                did: entry.hash().to_string(),
                role: KeyRole::Assertion,
                nonce: Some("x".into()),
                ttl: 60,
                version: None,
                out: None,
                force: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CreatePopError::ForceWithoutOut));
    }

    #[test]
    fn missing_entry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open_or_create(dir.path()).unwrap();
        let err = cmd_create_pop(
            &store,
            CreatePopArgs {
                did: "0a1b2c3d4e5f".into(),
                role: KeyRole::Assertion,
                nonce: Some("x".into()),
                ttl: 60,
                version: None,
                out: None,
                force: false,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CreatePopError::Resolve(ResolveError::NotFound(_))
        ));
    }

    #[test]
    fn auto_generated_nonce_is_22_chars() {
        let (_dir, store, entry) = make_store();
        let (_outdir, _path, jwt) = run_to_file(&store, &entry, KeyRole::Assertion, None, 30);
        let (_, payload_json, _) = split(&jwt);
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        let nonce = payload["nonce"].as_str().unwrap();
        // 16 raw bytes → 22 chars unpadded base64url.
        assert_eq!(nonce.len(), 22);
    }

    #[test]
    fn out_existing_file_without_force_is_rejected() {
        let (_dir, store, entry) = make_store();
        let outdir = tempfile::tempdir().unwrap();
        let path = outdir.path().join("pop.jwt");
        std::fs::write(&path, "preexisting").unwrap();

        let err = cmd_create_pop(
            &store,
            CreatePopArgs {
                did: entry.hash().to_string(),
                role: KeyRole::Assertion,
                nonce: Some("x".into()),
                ttl: 60,
                version: None,
                out: Some(path.clone()),
                force: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CreatePopError::FileExists { .. }));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "preexisting");
    }

    #[test]
    fn out_existing_file_with_force_overwrites() {
        let (_dir, store, entry) = make_store();
        let outdir = tempfile::tempdir().unwrap();
        let path = outdir.path().join("pop.jwt");
        std::fs::write(&path, "preexisting").unwrap();

        cmd_create_pop(
            &store,
            CreatePopArgs {
                did: entry.hash().to_string(),
                role: KeyRole::Assertion,
                nonce: Some("x".into()),
                ttl: 60,
                version: None,
                out: Some(path.clone()),
                force: true,
            },
        )
        .unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert_ne!(written, "preexisting");
        assert_eq!(written.split('.').count(), 3);
    }

    #[test]
    fn jwt_has_no_trailing_newline() {
        let (_dir, store, entry) = make_store();
        let (_outdir, _path, jwt) = run_to_file(&store, &entry, KeyRole::Assertion, Some("x"), 30);
        assert!(!jwt.ends_with('\n'));
    }
}
