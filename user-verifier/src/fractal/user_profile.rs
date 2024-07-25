use chrono::{DateTime, Utc};
use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::utils;

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct UserProfile {
    #[serde(deserialize_with = "utils::de_from_uuid")]
    pub uid: UserId,
    pub emails: Vec<Email>,
    pub phones: Vec<Phone>,
    pub wallets: Vec<Wallet>,
    pub verification_cases: Vec<VerificationCase>,
}

/// Fractal user id represented as hexadecimal string
#[derive(Debug, Clone, PartialEq)]
pub struct UserId(pub u128);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        uuid::Uuid::deserialize(deserializer).map(|uuid| Self(uuid.as_u128()))
    }
}

impl From<Uuid> for UserId {
    fn from(value: Uuid) -> Self {
        Self(value.as_u128())
    }
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct Email {
    pub address: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct Phone {
    pub number: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct Wallet {
    pub id: String,
    pub address: String,
    pub currency: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct VerificationCase {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(deserialize_with = "utils::de_array_separated_by_plus_sign")]
    pub level: Vec<VerificationLevel>,
    pub status: CaseStatus,
    pub credential: CredentialStatus,
    pub details: VerificationDetails,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationLevel {
    /// Verification by Face
    Uniqueness,
    /// KYC (always comes with Liveness)
    Basic,
    Plus,
    Liveness,
    Selfie,
    Sow,
    Telegram,
    Twitter,
    WalletEth,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum CaseStatus {
    Pending,
    Contacted,
    Done,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Deserialize, Debug)]
pub struct VerificationDetails {
    pub liveness: bool,
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Unavailable,
    Pending,
    Approved,
    Rejected,
}

impl UserProfile {
    pub fn is_wallet_matches(&self, wallet_address: Address) -> bool {
        self.wallets
            .iter()
            .any(
                |wallet| matches!(shared::utils::parse_evm_like_address(&wallet.address), Ok(address) if address == wallet_address)
            )
    }

    pub fn get_status(&mut self, levels: &[VerificationLevel]) -> VerificationStatus {
        // Sort by updated_at timestamp, most recent first
        self.verification_cases
            .sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let cases_status = self
            .verification_cases
            .iter()
            .filter_map(|case| {
                // Ignore cases other than related to requested levels
                for level in levels {
                    if !case.level.iter().any(|l| l == level) {
                        return None;
                    }
                }

                match case {
                    VerificationCase {
                        credential: CredentialStatus::Approved,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(VerificationStatus::Approved),
                    VerificationCase {
                        credential: CredentialStatus::Pending,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(VerificationStatus::Pending),
                    VerificationCase {
                        credential: CredentialStatus::Rejected,
                        details: VerificationDetails { liveness: true },
                        ..
                    } => Some(VerificationStatus::Rejected),
                    // Ignore verification cases without `liveness: true`
                    _ => None,
                }
            })
            .collect::<Vec<_>>();

        // If user has any approved case
        if cases_status
            .iter()
            .any(|status| status == &VerificationStatus::Approved)
        {
            return VerificationStatus::Approved;
        }

        // Otherwise, check the most recent result
        *cases_status
            .first()
            .unwrap_or(&VerificationStatus::Unavailable)
    }
}
