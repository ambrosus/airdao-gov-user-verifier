use chrono::{DateTime, Utc};
use ethabi::{Address, Hash};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::time::Duration;

use shared::utils::{self, encode_og_sbt_request, encode_sbt_request, encode_sno_sbt_request};

use crate::error::AppError;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignerConfig {
    #[serde(deserialize_with = "utils::de_secp256k1_signing_key")]
    pub signing_key: SigningKey,
    #[serde(deserialize_with = "utils::de_secs_duration")]
    pub request_lifetime: Duration,
    #[serde(deserialize_with = "utils::de_secs_duration")]
    pub sbt_lifetime: Duration,
    #[serde(deserialize_with = "utils::de_secs_timestamp_i64")]
    pub og_eligible_before: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SbtRequestSigner {
    pub config: SignerConfig,
}

#[derive(Serialize, Debug)]
pub struct SignedSBTRequest {
    #[serde(rename = "d")]
    pub data: String,
    pub v: u8,
    pub r: String,
    pub s: String,
}

impl SbtRequestSigner {
    pub fn new(config: SignerConfig) -> Self {
        Self { config }
    }

    fn sign_request(&self, encoded_req: Vec<u8>) -> Result<SignedSBTRequest, AppError> {
        let (sign, recovery_id) = self
            .config
            .signing_key
            .sign_digest_recoverable(Keccak256::new_with_prefix(&encoded_req))?;

        let (r, s) = sign.split_bytes();

        // Byte-array data (ABI encoded) is hex encoded to string, and should be hex decoded into byte-array for signature verification.
        Ok(SignedSBTRequest {
            data: hex::encode(encoded_req),
            v: recovery_id.to_byte() + 27,
            r: hex::encode(r),
            s: hex::encode(s),
        })
    }

    /// Creates SBT request and signs encoded data
    pub fn build_signed_sbt_request(
        &self,
        wallet: Address,
        user_id: u128,
        datetime: DateTime<Utc>,
    ) -> Result<SignedSBTRequest, AppError> {
        let req_expires_at = (datetime + self.config.request_lifetime).timestamp() as u64;
        let sbt_expires_at = (datetime + self.config.sbt_lifetime).timestamp() as u64;
        let encoded_req = encode_sbt_request(wallet, user_id, req_expires_at, sbt_expires_at);

        self.sign_request(encoded_req)
    }

    /// Creates OG SBT request and signs encoded data
    pub fn build_signed_og_sbt_request(
        &self,
        gov_wallet: Address,
        og_wallet: Address,
        tx_hash: Hash,
        datetime: DateTime<Utc>,
    ) -> Result<SignedSBTRequest, AppError> {
        let req_expires_at = (datetime + self.config.request_lifetime).timestamp() as u64;
        let encoded_req = encode_og_sbt_request(gov_wallet, og_wallet, tx_hash, req_expires_at);

        self.sign_request(encoded_req)
    }

    /// Creates SNO SBT request and signs encoded data
    pub fn build_signed_sno_sbt_request(
        &self,
        gov_wallet: Address,
        sno_wallet: Address,
        datetime: DateTime<Utc>,
    ) -> Result<SignedSBTRequest, AppError> {
        let req_expires_at = (datetime + self.config.request_lifetime).timestamp() as u64;
        let encoded_req = encode_sno_sbt_request(gov_wallet, sno_wallet, req_expires_at);

        self.sign_request(encoded_req)
    }
}

#[cfg(test)]
mod tests {
    use k256::{
        ecdsa::signature::DigestVerifier, elliptic_curve::scalar::ScalarPrimitive, Secp256k1,
    };
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_build_signed_sbt_request() {
        let user_id = uuid::Uuid::from_str("01020304-0506-1122-8877-665544332211")
            .unwrap()
            .as_u128();
        let config = SignerConfig {
            signing_key: SigningKey::from_slice(
                &hex::decode("356e70d642cc8ca8c3c502a5d3b210a1791f46c25fab9f8edde2f20f02e33fe7")
                    .unwrap(),
            )
            .unwrap(), //SigningKey::random(&mut rand::rngs::OsRng),
            request_lifetime: Duration::from_secs(180),
            sbt_lifetime: Duration::from_secs(86_400),
            og_eligible_before: Utc::now(),
        };

        let wallet = shared::utils::get_eth_address(
            config
                .signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        let signer = SbtRequestSigner::new(config.clone());
        let req = signer
            .build_signed_sbt_request(wallet, user_id, Utc::now())
            .unwrap();
        let signature = k256::ecdsa::Signature::from_scalars(
            ScalarPrimitive::<Secp256k1>::from_slice(&hex::decode(&req.r).unwrap())
                .unwrap()
                .to_bytes(),
            ScalarPrimitive::<Secp256k1>::from_slice(&hex::decode(req.s).unwrap())
                .unwrap()
                .to_bytes(),
        )
        .unwrap();

        // Verify signature
        config
            .signing_key
            .verifying_key()
            .verify_digest(
                Keccak256::new_with_prefix(hex::decode(&req.data).unwrap()),
                &signature,
            )
            .unwrap();

        // Recover and verify public key
        let recovered_key = k256::ecdsa::VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(hex::decode(&req.data).unwrap()),
            &signature,
            (req.v - 27).try_into().unwrap(),
        )
        .unwrap();

        assert_eq!(hex::encode(recovered_key.to_encoded_point(false).as_bytes()), "048cd99ec4cfdafd1c4a5e47396cb8a70ea02200b2e41407172de6148a8a142eded70725272e89bf073e63ef9b491259cfd014f3f3b477d9abf7090e4a6d391b64");
    }
}
