//! Issuer-side signing of credentials.
//!
//! v0.1.x integrates an **ephemeral fixture key** generated at
//! binary startup: a freshly-minted Ed25519 keypair that is held
//! in process memory only. The signed credentials this produces
//! are wire-shape compatible but **not cryptographically meaningful
//! across restarts** — each restart produces a new keypair, and the
//! issuer's published DID document does not advertise it.
//!
//! Real keystore integration (loading the assertion key from
//! `swiyu-didtool`'s on-disk keystore via the issuer row's
//! `signing_key_id`) lands in a follow-up slice. Until then the
//! issuer-oidc binary logs a loud warning at startup.

use ed25519_dalek::{Signer as _, SigningKey};

pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Generates a fresh Ed25519 keypair from the OS CSPRNG. Called
    /// once at issuer-oidc startup; the resulting `Signer` is held
    /// in `AppState` for the lifetime of the process.
    ///
    /// Uses `getrandom` directly rather than ed25519-dalek's optional
    /// `rand_core` feature, to avoid pulling in the extra feature
    /// flag for one call site.
    pub fn new_ephemeral_for_dev() -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("OS RNG must be available");
        let signing_key = SigningKey::from_bytes(&secret);
        Self { signing_key }
    }

    /// Signs `message` with EdDSA (Ed25519). Returns the raw 64-byte
    /// signature; the caller base64url-encodes it as the third
    /// segment of a JWS.
    pub fn sign_bytes(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("signing_key", &"<redacted>")
            .finish()
    }
}
