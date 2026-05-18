pub mod access_token;
pub mod api_token;
pub mod credential_offer;
pub mod credential_type;
pub mod ids;
pub mod issued_credential;
pub mod issuer;
pub mod issuer_credential_type;
pub mod nonce;
pub mod oauth2;
pub mod operation_task;
pub mod pre_auth_code;
pub mod secret_encryption_engine;
pub mod signing_engine;
pub mod status_list;
pub mod tenant;

pub use access_token::{AccessToken, AccessTokenHash, AccessTokenSecret};
pub use api_token::{ApiToken, ApiTokenHash, ApiTokenSecret};
pub use credential_offer::{CredentialOffer, CredentialOfferState};
pub use credential_type::{CredentialType, RevocationMode};

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("invalid input: {details}")]
    InvalidInput { details: String },
    #[error("state transition not allowed")]
    StateTransitionNotAllowed,
}
pub use ids::{
    ApiTokenId, CredentialOfferId, CredentialTypeId, IssuedCredentialId, IssuerId, StatusListId,
    TaskId, TenantId,
};
pub use issued_credential::{INTEGRITY_HASH_LEN, IssuedCredential, IssuedCredentialState};
pub use issuer::{Issuer, IssuerState, MarkOutcome};
pub use issuer_credential_type::IssuerCredentialTypeAssignment;
pub use nonce::{NonceHash, NonceSecret};
pub use oauth2::{
    AnyTokenProvider, OAuth2TokenProvider, ProviderRegistry, StaticTokenProvider, TokenAwareError,
    TokenProvider, TokenProviderError,
};
pub use operation_task::{OperationTask, StepOutcome, StepResult, TaskState, TaskType};
pub use pre_auth_code::PreAuthCode;
pub use secret_encryption_engine::{
    AnySecretEncryptionEngine, BuildError as SecretEncryptionEngineBuildError, Ciphertext,
    DevSecretEncryptionEngine, SecretEncryptionEngine, SecretEncryptionError,
    VaultSecretEncryptionEngine, VaultSecretEncryptionEngineConfig,
    build_from_env as build_secret_encryption_engine_from_env,
};
pub use signing_engine::{
    AnySigningEngine, BuildError as SigningEngineBuildError, DevSigningEngine, GeneratedKeyPair,
    KeyAlgorithm, KeyPairId, KeyRole, RawPublicKey, Signature, SigningEngine, SigningEngineError,
    VaultSigningEngine, VaultSigningEngineConfig, build_from_env as build_signing_engine_from_env,
};
pub use status_list::{BITSTRING_BYTES, StatusList, StatusListIndex, StatusValue};
pub use tenant::Tenant;
