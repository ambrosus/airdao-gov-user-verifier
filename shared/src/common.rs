use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, TimeZone, Utc};
use ethabi::{encode, Address, ParamType, Token};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

use crate::utils::{convert_to_claims_with_expiration, decode_sbt_request};

/// Minimum time required before oauth2 token expires in seconds
static OAUTH_TOKEN_MINIMUM_LIFETIME: u64 = 300;

/// Verification request struct to check if User has approved Fractal's face verification
/// to acquire signed SBT mint request
#[derive(Deserialize, Debug)]
pub struct VerifyAccountRequest {
    /// User's profile
    pub user: UserProfile,
    /// Fractal token's kind
    #[serde(flatten)]
    pub token: TokenKind,
}

/// Enumerable which represents a response to a User for his verification request
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum VerifyAccountResponse {
    /// Approved variant response if User is eligible to mint Human SBT token
    Approved(ApprovedResponse),
    /// Pending variant response if User's face verification is still pending at Fractal side
    Pending(PendingResponse),
}

/// Signed response for a User with approved face verification
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ApprovedResponse {
    pub msg: String,
}

/// Response for a User whos face verification is pending for final decision
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct PendingResponse {
    pub token: OAuthToken,
}

/// Signed SBT mint request to be returned to User for a subsequent `sbtMint` smart-contract call
#[derive(Deserialize, Serialize, Debug)]
pub struct SignedSBTRequest {
    #[serde(rename = "d")]
    pub data: String,
    pub v: u8,
    pub r: String,
    pub s: String,
}

/// Decoded SBT signed request to be used by a mocker
#[derive(Debug, Clone, Serialize)]
pub struct SBTRequest {
    pub caller: Address,
    pub user_id: String,
    pub req_expires_at: u64,
    pub sbt_expires_at: u64,
}

/// User's profile information struct
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub wallet: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<serde_email::Email>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twitter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<url::Url>,
}

impl UserInfo {
    pub fn is_profile_finished(&self) -> bool {
        self.email.is_some()
            && self.name.is_some()
            && self.role.is_some()
            && self.bio.is_some()
            && self.avatar.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    /// User's public profile information    
    pub info: UserInfo,
    #[serde(flatten)]
    pub status: UserProfileStatus,
}

#[derive(Deserialize, Serialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RawUserProfile {
    /// Quiz questionnaire solve result
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiz_solved: Option<bool>,
    /// Timestamp in millis till user profile is blocked
    ///
    /// Do not allows users to solve quiz and continue with Fractal face verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_until: Option<u64>,
    /// Users profile information
    #[serde(flatten)]
    pub info: UserInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserProfileStatus {
    /// Profile is blocked (until timestamp in millis) to be verified by face via Fractal
    Blocked {
        #[serde(rename = "blockedUntil")]
        blocked_until: u64,
    },
    Incomplete {
        /// Indicates if user solved a Quiz questionnaire
        #[serde(rename = "quizSolved")]
        quiz_solved: bool,
        /// Indicates if profile has all mandatory information filled
        #[serde(rename = "finishedProfile")]
        finished_profile: bool,
    },
    /// Profile is complete and ready to be verified by Fractal
    Complete(CompletionToken),
}

/// Profile completion JWT token for an access to Fractal user verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletionToken {
    pub token: String,
}

impl From<String> for CompletionToken {
    fn from(token: String) -> Self {
        Self { token }
    }
}

impl From<&str> for CompletionToken {
    fn from(token: &str) -> Self {
        Self {
            token: token.to_owned(),
        }
    }
}

impl Default for UserProfileStatus {
    fn default() -> Self {
        Self::Incomplete {
            quiz_solved: false,
            finished_profile: false,
        }
    }
}

impl UserProfile {
    pub fn new(
        raw_profile: RawUserProfile,
        lifetime: Duration,
        secret: &[u8],
    ) -> anyhow::Result<Self> {
        let finished_profile = raw_profile.info.is_profile_finished();

        match raw_profile {
            RawUserProfile {
                blocked_until: Some(ts),
                info,
                ..
            } if ts > Utc::now().timestamp_millis() as u64 => Ok(Self {
                info,
                status: UserProfileStatus::Blocked { blocked_until: ts },
            }),
            RawUserProfile {
                quiz_solved: Some(true),
                info,
                ..
            } if finished_profile => {
                let claims = convert_to_claims_with_expiration(&info, Utc::now() + lifetime)?;

                let status = jsonwebtoken::encode(
                    &jsonwebtoken::Header::default(),
                    &claims,
                    &jsonwebtoken::EncodingKey::from_secret(secret),
                )
                .map_err(anyhow::Error::from)
                .map(|token| UserProfileStatus::Complete(token.into()))?;

                Ok(Self { info, status })
            }
            RawUserProfile {
                quiz_solved: Some(false) | None,
                info,
                ..
            } => Ok(Self {
                info,
                status: UserProfileStatus::Incomplete {
                    quiz_solved: false,
                    finished_profile,
                },
            }),
            RawUserProfile {
                quiz_solved: Some(true),
                info,
                ..
            } => Ok(Self {
                info,
                status: UserProfileStatus::Incomplete {
                    quiz_solved: true,
                    finished_profile,
                },
            }),
        }
    }

    pub fn is_verification_blocked(&self) -> bool {
        matches!(self.status, UserProfileStatus::Blocked { blocked_until } if blocked_until > Utc::now().timestamp_millis() as u64)
    }
}

impl TryFrom<RawUserRegistrationToken> for UserInfo {
    type Error = anyhow::Error;

    fn try_from(token: RawUserRegistrationToken) -> Result<Self, Self::Error> {
        let wallet = ethereum_types::Address::from(<[u8; 20]>::try_from(
            hex::decode(token.checksum_wallet)?.as_slice(),
        )?);

        Ok(Self {
            wallet,
            email: Some(token.email),
            ..Default::default()
        })
    }
}

/// Session JWT token for an access to MongoDB
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionToken {
    pub token: String,
}

/// The claims part of session JWT token
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawSessionToken {
    /// User's wallet address
    #[serde(rename = "wallet")]
    pub checksum_wallet: String,
    /// Expiration date for a session JWT token
    pub expires_at: u64,
}

impl RawSessionToken {
    /// Verifies that session JWT token is not expired
    pub fn verify(&self) -> bool {
        self.expires_at > Utc::now().timestamp_millis() as u64
    }
}

impl SessionToken {
    /// Creates a new session JWT token for specific User's wallet address
    pub fn new(token: RawSessionToken, secret: &[u8]) -> Result<Self, anyhow::Error> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &token,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .map_err(anyhow::Error::from)
        .map(|token| Self { token })
    }

    /// Verifies that session JWT token is valid and not expired. Returns extracted User's wallet address
    pub fn verify(&self, secret: &[u8]) -> Result<String, anyhow::Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());
        validation.set_required_spec_claims(&<[&str; 0]>::default());

        let token_data = jsonwebtoken::decode::<RawSessionToken>(
            &self.token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )?;

        if !token_data.claims.verify() {
            Err(anyhow::Error::msg("Session token expired"))
        } else {
            Ok(token_data.claims.checksum_wallet)
        }
    }
}

/// Custom message which User has been asked to sign with his wallet secret to prove that he is an owner of a wallet
#[derive(Debug, Deserialize)]
pub struct WalletSignedMessage {
    #[serde(rename = "msg")]
    pub message: String,
    pub sign: String,
}

impl TryFrom<SignedSBTRequest> for SBTRequest {
    type Error = anyhow::Error;

    fn try_from(value: SignedSBTRequest) -> Result<Self, Self::Error> {
        // TODO: verify signature
        decode_sbt_request(hex::decode(value.data)?)
    }
}

/// Fractal token kind
#[derive(Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum TokenKind {
    /// First authorization token which could be used to acquire OAuth token from Fractal to access User's profile data
    AuthorizationCode {
        auth_code: String,
        redirect_uri: String,
    },
    /// OAuth token to access User's profile data from Fractal
    OAuth {
        token: OAuthToken,
        redirect_uri: String,
    },
}

/// Fractal OAuth token struct
#[derive(Debug, PartialEq, Clone)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Fractal OAuth token lifetime info
#[derive(Deserialize, Debug)]
pub struct TokenLifetime {
    pub expires_in: u64,
    pub created_at: u64,
}

impl Serialize for OAuthToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded_raw = encode(&[
            Token::String(self.access_token.clone()),
            Token::String(self.refresh_token.clone()),
            Token::FixedBytes(self.expires_at.timestamp_millis().to_be_bytes().to_vec()),
        ]);

        let encoded = general_purpose::STANDARD.encode(encoded_raw);

        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for OAuthToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: String = Deserialize::deserialize(deserializer)?;

        let encoded_raw = general_purpose::STANDARD.decode(encoded).map_err(|e| {
            de::Error::custom(format!(
                "Failed to deserialize base64 encoded oauth token {e:?}"
            ))
        })?;

        let tokens = ethabi::decode(
            &[
                ParamType::String,
                ParamType::String,
                ParamType::FixedBytes(8),
            ],
            &encoded_raw,
        )
        .map_err(|e| {
            de::Error::custom(format!("Failed to deserialize encoded oauth token {e:?}"))
        })?;

        match <Vec<Token> as TryInto<[Token; 3]>>::try_into(tokens) {
            Ok(
                [Token::String(access_token), Token::String(refresh_token), Token::FixedBytes(expires_at)],
            ) => Ok(Self {
                access_token,
                refresh_token,
                expires_at: super::utils::parse_datetime(&expires_at).map_err(de::Error::custom)?,
            }),
            _ => Err(de::Error::custom("Unknown oauth token format")),
        }
    }
}

impl TokenLifetime {
    /// Returns UTC datetime when Fractal OAuth token will expire
    pub fn expires_at(&self) -> DateTime<Utc> {
        Utc.timestamp_nanos((self.created_at + self.expires_in) as i64 * 1_000_000_000)
    }
}

impl OAuthToken {
    /// Returns if Fractal OAuth token requires to be refreshed
    pub fn requires_refresh(&self) -> bool {
        Utc::now() + Duration::from_secs(OAUTH_TOKEN_MINIMUM_LIFETIME) >= self.expires_at
    }
}

/// Registration JWT token used to register User's profile first time in AirDao DB
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRegistrationToken {
    pub token: String,
}

/// Registration JWT token's claims struct with User's basic profile info
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawUserRegistrationToken {
    /// User's wallet address
    #[serde(rename = "wallet")]
    pub checksum_wallet: String,
    /// User's email
    pub email: serde_email::Email,
    /// Expiration date in millis after registration token will become invalid
    pub expires_at: u64,
}

impl RawUserRegistrationToken {
    /// Verifies that registration token is not expired
    pub fn verify(&self) -> bool {
        self.expires_at > Utc::now().timestamp_millis() as u64
    }
}

impl UserRegistrationToken {
    /// Creates new registration JWT token for a User
    pub fn new(token: RawUserRegistrationToken, secret: &[u8]) -> Result<Self, anyhow::Error> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &token,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .map_err(anyhow::Error::from)
        .map(|token| Self { token })
    }

    /// Verifies that registration JWT token is valid and not expired. Returns User's basic profile info
    pub fn verify(&self, secret: &[u8]) -> Result<RawUserRegistrationToken, anyhow::Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());
        validation.set_required_spec_claims(&<[&str; 0]>::default());

        let token_data = jsonwebtoken::decode::<RawUserRegistrationToken>(
            &self.token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )?;

        if !token_data.claims.verify() {
            Err(anyhow::Error::msg("Registration token expired"))
        } else {
            Ok(token_data.claims)
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDbConfig {
    pub base_url: String,
}

#[cfg(test)]
mod tests {
    use crate::common::CompletionToken;

    use super::{RawUserProfile, UserProfile, UserProfileStatus};

    #[test]
    fn test_de_raw_user_profile() {
        serde_json::from_str::<RawUserProfile>(
            r#"
          {
            "quizSolved": true,
            "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
            "name": "test user name",
            "role": "test role",
            "email": "test@test.com",
            "telegram": "@telegram",
            "twitter": "@twitter",
            "bio": "some test bio",
            "avatar": "http://test.com"
          }
        "#,
        )
        .unwrap();
    }

    #[test]
    fn test_de_user_profile() {
        assert_matches::assert_matches!(
            serde_json::from_str::<UserProfile>(
                r#"
                    {
                        "info": {
                            "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
                            "name": "test user name",
                            "role": "test role",
                            "email": "test@test.com",
                            "telegram": "@telegram",
                            "twitter": "@twitter",
                            "bio": "some test bio",
                            "avatar": "http://test.com"    
                        },
                        "blockedUntil": 100000
                    }
                "#
            ),
            Ok(UserProfile {
                status: UserProfileStatus::Blocked {
                    blocked_until: 100000
                },
                ..
            })
        );

        assert_matches::assert_matches!(
            serde_json::from_str::<UserProfile>(
                r#"
                    {
                        "info": {
                            "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
                            "name": "test user name",
                            "role": "test role",
                            "email": "test@test.com",
                            "telegram": "@telegram",
                            "twitter": "@twitter",
                            "bio": "some test bio",
                            "avatar": "http://test.com"    
                        },
                        "quizSolved": false,
                        "finishedProfile": false
                    }
                "#
            ),
            Ok(UserProfile {
                status: UserProfileStatus::Incomplete {
                    quiz_solved: false,
                    finished_profile: false,
                },
                ..
            })
        );

        assert_matches::assert_matches!(
            serde_json::from_str::<UserProfile>(
                r#"
                    {
                        "info": {
                            "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
                            "name": "test user name",
                            "role": "test role",
                            "email": "test@test.com",
                            "telegram": "@telegram",
                            "twitter": "@twitter",
                            "bio": "some test bio",
                            "avatar": "http://test.com"    
                        },
                        "token": "some_verification_token"
                    }
                "#
            ),
            Ok(UserProfile {
                status: UserProfileStatus::Complete(CompletionToken { token }),
                ..
            }) if token.as_str() == "some_verification_token"
        );
    }
}
