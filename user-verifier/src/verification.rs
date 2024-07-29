use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Utc};
use ethabi::{Address, Hash};

use shared::common::{ApprovedResponse, PendingResponse, VerifyResponse};

use crate::{
    error::AppError,
    fractal::{VerificationStatus, VerifiedUser},
    signer::SbtRequestSigner,
};

pub fn create_verify_account_response(
    signer: &SbtRequestSigner,
    wallet: Address,
    user: VerifiedUser,
    datetime: DateTime<Utc>,
) -> Result<VerifyResponse, AppError> {
    match user.status.uniqueness {
        VerificationStatus::Approved => {
            let sbt_req = signer.build_signed_sbt_request(wallet, user.user_id.0, datetime)?;

            let msg = general_purpose::STANDARD.encode(serde_json::to_string(&sbt_req)?);

            Ok(VerifyResponse::Approved(ApprovedResponse { msg }))
        }
        VerificationStatus::Pending => Ok(VerifyResponse::Pending(PendingResponse {
            token: user.token,
        })),
        VerificationStatus::Rejected => Err(AppError::VerificationRejected),
        VerificationStatus::Unavailable => Err(AppError::VerificationNotCompleted),
    }
}

pub fn create_verify_og_response(
    signer: &SbtRequestSigner,
    gov_wallet: Address,
    og_wallet: Address,
    tx_hash: Hash,
    datetime: DateTime<Utc>,
) -> Result<VerifyResponse, AppError> {
    let sbt_req = signer.build_signed_og_sbt_request(gov_wallet, og_wallet, tx_hash, datetime)?;

    let msg = general_purpose::STANDARD.encode(serde_json::to_string(&sbt_req)?);

    Ok(VerifyResponse::Approved(ApprovedResponse { msg }))
}

pub fn create_verify_node_owner_response(
    signer: &SbtRequestSigner,
    gov_wallet: Address,
    sno_wallet: Address,
    server_nodes_manager: Address,
    datetime: DateTime<Utc>,
) -> Result<VerifyResponse, AppError> {
    let sbt_req = signer.build_signed_sno_sbt_request(
        gov_wallet,
        sno_wallet,
        server_nodes_manager,
        datetime,
    )?;

    let msg = general_purpose::STANDARD.encode(serde_json::to_string(&sbt_req)?);

    Ok(VerifyResponse::Approved(ApprovedResponse { msg }))
}

#[cfg(test)]
mod tests {
    use ecdsa::SigningKey;
    use std::time::Duration;
    use uuid::Uuid;

    use shared::common::OAuthToken;

    use super::*;
    use crate::{
        fractal::{UserId, UserStatus},
        signer::SignerConfig,
    };

    #[test]
    fn test_verify_account_response() {
        let fake_datetime = DateTime::<Utc>::default();
        let user_id: UserId = Uuid::parse_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8")
            .unwrap()
            .into();
        let token = OAuthToken {
            access_token: "some_access_token".to_owned(),
            refresh_token: "some_refresh_token".to_owned(),
            expires_at: Utc::now(),
        };
        let signer = SbtRequestSigner::new(SignerConfig {
            signing_key: SigningKey::from_slice(
                &hex::decode("356e70d642cc8ca8c3c502a5d3b210a1791f46c25fab9f8edde2f20f02e33fe7")
                    .unwrap(),
            )
            .unwrap(),
            request_lifetime: Duration::from_secs(180),
            sbt_lifetime: Duration::from_secs(86_400),
            og_eligible_before: Utc::now(),
        });

        let wallet = shared::utils::get_eth_address(
            signer
                .config
                .signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        struct TestCase {
            name: &'static str,
            input: VerificationStatus,
            expected: Result<VerifyResponse, String>,
        }

        let test_cases = [
            TestCase {
                name: "Verification is not completed",
                input: VerificationStatus::Unavailable,
                expected: Err(AppError::VerificationNotCompleted.to_string()),
            },
            TestCase {
                name: "Verification is rejected",
                input: VerificationStatus::Rejected,
                expected: Err(AppError::VerificationRejected.to_string()),
            },
            TestCase {
                name: "Verification is pending",
                input: VerificationStatus::Pending,
                expected: Ok(VerifyResponse::Pending(PendingResponse {
                    token: token.clone(),
                })),
            },
            TestCase {
                name: "Verification is approved",
                input: VerificationStatus::Approved,
                expected: Ok(VerifyResponse::Approved(ApprovedResponse {
                    msg: "eyJkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwOTNhMTZiNDAzODcyOWYwYzQ5OGZkZDlhNzBlMDVmYmIzM2Y3OWEyZDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwYTFhMmEzYTRiMWIyYzFjMmQxZDJkM2Q0ZDVkNmQ3ZDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMGI0MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxNTE4MCIsInYiOjI4LCJyIjoiYmJhZDJmZmVhZTgzZWIzNTYzZDVmY2UxMTRjZGUyY2U2YzAwMDkzMDAyNTYwYzVkNjcwMWIyZTg1OTU2NTJlNiIsInMiOiIxOWQyZTkzNmYyZGVmMmE0MzA4ZDU3NzQzN2EzMWQyMTI4MGFjZGZiYjQwYjNmMmYzNzZjMzY4NTQzZWEyMzkzIn0=".to_owned(),
                })),
            },
        ];

        for test in test_cases {
            let result = create_verify_account_response(
                &signer,
                wallet,
                VerifiedUser {
                    user_id: user_id.clone(),
                    token: token.clone(),
                    status: UserStatus {
                        uniqueness: test.input,
                        basic: VerificationStatus::Unavailable,
                    },
                },
                fake_datetime,
            )
            .map_err(|e| e.to_string());
            assert_eq!(result, test.expected, "Test case `{}` failed", test.name);
        }
    }
}
