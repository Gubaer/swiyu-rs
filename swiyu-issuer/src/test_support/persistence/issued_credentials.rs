use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use crate::domain::{
    BITSTRING_BYTES, CredentialOffer, INTEGRITY_HASH_LEN, IssuedCredential, IssuedCredentialState,
    Issuer, PreAuthCode, StatusListId, StatusListIndex, StatusValue,
};
use crate::persistence;
use crate::test_support::fixtures::SAMPLE_HOLDER_KEY_JKT;
use crate::test_support::persistence::credential_offers;
use crate::test_support::persistence::status_lists::read_slot;

pub async fn fetch_state(pool: &PgPool, credential: &IssuedCredential) -> String {
    sqlx::query_scalar("SELECT state FROM issued_credentials WHERE id = $1")
        .bind(credential.id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

pub async fn fetch_status_bit(pool: &PgPool, credential: &IssuedCredential) -> StatusValue {
    let bitstring: Vec<u8> = sqlx::query_scalar("SELECT bitstring FROM status_lists WHERE id = $1")
        .bind(credential.status_list_id.bare())
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(bitstring.len(), BITSTRING_BYTES);
    read_slot(&bitstring, credential.status_list_index)
}

pub async fn seed_offer(pool: &PgPool, issuer: &Issuer, vct: &str) -> CredentialOffer {
    let offer = CredentialOffer::new(
        issuer.tenant_id.clone(),
        issuer.id.clone(),
        vct.into(),
        serde_json::json!({}),
        PreAuthCode::generate(),
        Utc::now() + Duration::minutes(5),
    );
    credential_offers::insert(pool, &offer).await;
    offer
}

/// Builder for seeding an `IssuedCredential` row (plus its backing
/// offer and, optionally, a non-default lifecycle state and status-bit
/// slot). Defaults match the most common shape: vct `"vc-test"`,
/// state `Active`, status bit `Valid`, issued-at now. Override only
/// the fields the test cares about.
#[must_use]
pub struct CredentialSeed<'a> {
    pool: &'a PgPool,
    issuer: &'a Issuer,
    list_id: &'a StatusListId,
    list_index: u32,
    vct: &'a str,
    state: IssuedCredentialState,
    status_bit: StatusValue,
    issued_at: DateTime<Utc>,
}

impl<'a> CredentialSeed<'a> {
    pub fn new(
        pool: &'a PgPool,
        issuer: &'a Issuer,
        list_id: &'a StatusListId,
        list_index: u32,
    ) -> Self {
        Self {
            pool,
            issuer,
            list_id,
            list_index,
            vct: "vc-test",
            state: IssuedCredentialState::Active,
            status_bit: StatusValue::Valid,
            issued_at: Utc::now(),
        }
    }

    pub fn vct(mut self, vct: &'a str) -> Self {
        self.vct = vct;
        self
    }

    pub fn state(mut self, state: IssuedCredentialState) -> Self {
        self.state = state;
        self
    }

    pub fn status_bit(mut self, status_bit: StatusValue) -> Self {
        self.status_bit = status_bit;
        self
    }

    pub fn issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.issued_at = issued_at;
        self
    }

    pub async fn insert(self) -> IssuedCredential {
        let offer = seed_offer(self.pool, self.issuer, self.vct).await;
        let credential = IssuedCredential::new(
            self.issuer.tenant_id.clone(),
            self.issuer.id.clone(),
            offer.id,
            self.vct.into(),
            SAMPLE_HOLDER_KEY_JKT.into(),
            self.list_id.clone(),
            StatusListIndex::try_from(self.list_index).unwrap(),
            [0u8; INTEGRITY_HASH_LEN],
            self.issued_at,
            self.issued_at + Duration::days(365),
        );
        let mut conn = self.pool.acquire().await.unwrap();
        persistence::issued_credentials::insert(&mut conn, &credential)
            .await
            .unwrap();
        if self.state != IssuedCredentialState::Active {
            persistence::issued_credentials::set_state(
                &mut conn,
                &credential.tenant_id,
                &credential.id,
                self.state,
            )
            .await
            .unwrap();
        }
        if self.status_bit != StatusValue::Valid {
            persistence::status_lists::write_bit(
                &mut conn,
                self.list_id,
                credential.status_list_index,
                self.status_bit,
            )
            .await
            .unwrap();
        }
        IssuedCredential {
            state: self.state,
            ..credential
        }
    }
}
