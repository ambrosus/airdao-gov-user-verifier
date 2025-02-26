use anyhow::anyhow;
use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, TimeZone, Utc};
use cid::Cid;
use ethabi::{encode, Address, ParamType, Token};
use ethereum_types::U256;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, fmt::Display, ops::Deref, str::FromStr, time::Duration};

use crate::utils::{self, decode_sbt_request};

/// Minimum time required before oauth2 token expires in seconds
static OAUTH_TOKEN_MINIMUM_LIFETIME: u64 = 300;

/// Verification request struct to check if User has approved Fractal's face verification
/// to acquire signed SBT mint request
#[derive(Deserialize, Debug)]
pub struct VerifyFractalUserRequest {
    /// User's profile
    pub user: User,
    /// Fractal token's kind
    #[serde(flatten)]
    pub fractal_token: TokenKind,
}

/// Verification request struct to check if user's wallet is eligible to acquire signed SBT mint request
#[derive(Deserialize, Debug)]
pub struct VerifyWalletRequest {
    /// User's profile
    pub user: User,
    /// Optional Base64-encoded JSON-serialized [`WalletSignedMessage`] data struct
    pub data: Option<String>,
}

/// Enumerable which represents a response to a User for his verification request
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum VerifyResponse {
    /// Approved variant response
    Approved(ApprovedResponse),
    /// Pending variant response if User's face verification is still pending at Fractal side
    Pending(PendingResponse),
}

/// Signed response for a User with approved verification
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

/// JSON-serialized request passed as POST-data to `/update-user-sbt` endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserSBTRequest {
    pub wallet: Address,
    pub token: SessionToken,
    #[serde(flatten)]
    pub kind: UpdateSBTKind,
}

/// JSON-serialized request passed as POST-data to `/update-reward` endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRewardRequest {
    pub token: SessionToken,
    #[serde(flatten)]
    pub kind: UpdateRewardKind,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateSBTKind {
    Upsert(SBTInfo),
    Remove {
        #[serde(alias = "address")]
        sbt_address: Address,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdateRewardKind {
    Grant(RewardInfo),
    Claim {
        #[serde(rename = "blockNumber")]
        block_number: u64,
        wallet: Address,
        id: BatchId,
    },
    Revert {
        #[serde(rename = "blockNumber")]
        block_number: u64,
        id: BatchId,
    },
}

/// User's profile information struct
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, PartialOrd, Ord, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SBTInfo {
    pub address: Address,
    pub name: String,
    pub issued_at_block: u64,
}

/// All rewards information struct
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Rewards {
    pub id: BatchId,
    pub rewards_by_wallet: HashMap<Address, RewardInfo>,
    pub timestamp: TimestampSeconds,
    #[serde(default, skip_serializing_if = "RewardStatus::is_granted")]
    pub status: RewardStatus,
}

impl From<Rewards> for RewardsDbEntry {
    fn from(value: Rewards) -> Self {
        Self {
            id: value.id,
            wallets: value
                .rewards_by_wallet
                .into_iter()
                .map(|(wallet, info)| (wallet, RewardDbEntry::from(info)))
                .collect(),
            status: value.status,
        }
    }
}

impl From<RewardInfo> for RewardDbEntry {
    fn from(value: RewardInfo) -> Self {
        Self {
            grantor: value.grantor,
            amount: value.amount,
            timestamp: value.timestamp,
            event_name: value.event_name,
            region: value.region,
            community: value.community,
            pseudo: value.pseudo,
            status: value.status,
        }
    }
}

/// User's reward information struct
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RewardInfo {
    pub id: BatchId,
    pub grantor: Address,
    pub wallet: Address,
    pub amount: U256,
    pub timestamp: TimestampSeconds,
    pub event_name: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudo: Option<String>,
    #[serde(default, skip_serializing_if = "RewardStatus::is_granted")]
    pub status: RewardStatus,
}

/// User's profile information struct stored in MongoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SBTDbEntry {
    pub name: String,
    pub issued_at_block: u64,
}

/// All rewards information struct stored in MongoDB
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardsDbEntry {
    pub id: BatchId,
    pub wallets: HashMap<Address, RewardDbEntry>,
    #[serde(default)]
    pub status: RewardStatus,
}

#[derive(
    Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize, Clone, Default, Copy,
)]
pub struct BatchId(pub u64);

/// User's reward information struct stored in MongoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardDbEntry {
    pub grantor: Address,
    pub amount: U256,
    pub timestamp: TimestampSeconds,
    pub event_name: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudo: Option<String>,
    #[serde(default, skip_serializing_if = "RewardStatus::is_granted")]
    pub status: RewardStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, Copy)]
pub struct TimestampSeconds(pub u64);

impl PartialOrd for TimestampSeconds {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl PartialEq for TimestampSeconds {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<DateTime<Utc>> for TimestampSeconds {
    fn from(value: DateTime<Utc>) -> Self {
        Self(value.timestamp() as u64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Default)]
#[serde(rename_all = "camelCase")]
pub enum RewardStatus {
    #[default]
    Granted,
    Claimed,
    Reverted,
}

impl RewardStatus {
    fn is_granted(&self) -> bool {
        self == &RewardStatus::Granted
    }
}

/// User's profile information struct
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "utils::de_opt_cid"
    )]
    pub avatar: Option<WrappedCid>,
}

impl UserProfile {
    pub fn is_finished(&self) -> bool {
        self.email.is_some()
            && self.name.is_some()
            && self.role.is_some()
            && self.bio.is_some()
            && self.avatar.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// User's unique governor wallet address
    pub wallet: Address,
    /// User's public profile information
    pub profile: Option<UserProfile>,
    #[serde(flatten)]
    pub status: UserProfileStatus,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UserDbEntry {
    /// User's unique governor wallet address
    pub wallet: Address,
    /// Quiz questionnaire solve result
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiz_solved: Option<bool>,
    /// Timestamp in millis till user profile is blocked
    ///
    /// Do not allows users to solve quiz and continue with Fractal face verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_until: Option<u64>,
    /// Users profile information
    #[serde(default, skip_serializing_if = "Option::is_none", flatten)]
    pub profile: Option<UserProfile>,
    /// Users profile information
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sbts: HashMap<Address, SBTDbEntry>,
}

impl From<User> for UserDbEntry {
    fn from(user: User) -> Self {
        Self {
            wallet: user.wallet,
            quiz_solved: None,
            blocked_until: None,
            profile: user.profile,
            sbts: Default::default(),
        }
    }
}

impl From<UserEmailUpdateRequest> for UserProfile {
    fn from(req: UserEmailUpdateRequest) -> Self {
        Self {
            email: Some(req.email),
            ..Default::default()
        }
    }
}

impl UserDbEntry {
    pub fn is_profile_finished(&self) -> bool {
        self.profile
            .as_ref()
            .map(|profile| profile.is_finished())
            .unwrap_or_default()
    }
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

/// User profile verification token with expiration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserProfileVerificationToken {
    wallet: Address,
    exp: i64,
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

impl User {
    pub fn new(
        db_entry: UserDbEntry,
        expires_at: DateTime<Utc>,
        secret: &[u8],
    ) -> anyhow::Result<Self> {
        let finished_profile = db_entry.is_profile_finished();

        match db_entry {
            UserDbEntry {
                wallet,
                blocked_until: Some(ts),
                profile,
                ..
            } if ts > Utc::now().timestamp_millis() as u64 => Ok(Self {
                wallet,
                profile,
                status: UserProfileStatus::Blocked { blocked_until: ts },
            }),
            UserDbEntry {
                wallet,
                quiz_solved: Some(true),
                profile,
                ..
            } if finished_profile => {
                let status = jsonwebtoken::encode(
                    &jsonwebtoken::Header::default(),
                    &UserProfileVerificationToken {
                        wallet,
                        exp: expires_at.timestamp(),
                    },
                    &jsonwebtoken::EncodingKey::from_secret(secret),
                )
                .map_err(anyhow::Error::from)
                .map(|token| UserProfileStatus::Complete(token.into()))?;

                Ok(Self {
                    wallet,
                    profile,
                    status,
                })
            }
            UserDbEntry {
                wallet,
                quiz_solved: Some(false) | None,
                profile,
                ..
            } => Ok(Self {
                wallet,
                profile,
                status: UserProfileStatus::Incomplete {
                    quiz_solved: false,
                    finished_profile,
                },
            }),
            UserDbEntry {
                wallet,
                quiz_solved: Some(true),
                profile,
                ..
            } => Ok(Self {
                wallet,
                profile,
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

    pub fn is_complete(&self, secret: &[u8]) -> bool {
        // Check if user profile status is complete
        if let UserProfileStatus::Complete(CompletionToken { token }) = &self.status {
            let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());

            // User profile verification JWT token check
            let Ok(token_data) = jsonwebtoken::decode::<UserProfileVerificationToken>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(secret),
                &validation,
            ) else {
                return false;
            };

            // Check that user profile verification token corresponds to the same wallet
            token_data.claims.wallet == self.wallet
        } else {
            false
        }
    }
}

/// Session JWT token for an access to MongoDB
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SessionToken(String);

impl std::fmt::Display for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<String> for SessionToken {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl Deref for SessionToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl From<&str> for SessionToken {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// The claims part of session JWT token
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawSessionToken {
    /// Session token kind
    #[serde(flatten)]
    pub kind: SessionTokenKind,
    /// Expiration date for a session JWT token
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionTokenKind {
    Wallet {
        /// User's gov wallet address
        #[serde(rename = "wallet")]
        checksum_wallet: String,
    },
    Internal {},
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
        .map(Self)
    }

    /// Verifies that session JWT token is valid and not expired. Returns extracted User's wallet address
    pub fn verify_wallet(&self, secret: &[u8]) -> Result<String, anyhow::Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());
        validation.set_required_spec_claims(&<[&str; 0]>::default());

        let token = jsonwebtoken::decode::<RawSessionToken>(
            self.as_ref(),
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )?
        .claims;

        if !token.verify() {
            return Err(anyhow!("Session token expired"));
        }

        match token {
            RawSessionToken {
                kind: SessionTokenKind::Wallet { checksum_wallet },
                ..
            } => Ok(checksum_wallet),
            _ => Err(anyhow!("Invalid session token kind")),
        }
    }

    /// Verifies that session JWT token is valid for internal usage and not expired
    pub fn verify_internal(&self, secret: &[u8]) -> Result<(), anyhow::Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());
        validation.set_required_spec_claims(&<[&str; 0]>::default());

        let token = jsonwebtoken::decode::<RawSessionToken>(
            self.as_ref(),
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )?
        .claims;

        if !token.verify() {
            return Err(anyhow!("Session token expired"));
        }

        match token {
            RawSessionToken {
                kind: SessionTokenKind::Internal {},
                ..
            } => Ok(()),
            _ => Err(anyhow!("Invalid session token kind")),
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

impl std::str::FromStr for WalletSignedMessage {
    type Err = anyhow::Error;

    fn from_str(encoded_message: &str) -> Result<Self, Self::Err> {
        let decoded = general_purpose::STANDARD
            .decode(encoded_message)
            .map_err(|e| anyhow!("Failed to deserialize base64 encoded message {e:?}"))?;

        serde_json::from_slice::<WalletSignedMessage>(&decoded)
            .map_err(|e| anyhow!("Failed to deserialize wallet signed message {e:?}"))
    }
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

/// User email change request encoded into confirmation token
#[derive(Debug, Deserialize)]
pub struct UserEmailUpdateRequest {
    pub wallet: Address,
    pub old_email: Option<serde_email::Email>,
    pub email: serde_email::Email,
}

/// Email confirmation JWT token used to set or update email to User's profile in AirDao DB
#[derive(Debug, Serialize, Deserialize)]
pub struct UserEmailConfirmationToken {
    pub token: String,
}

impl UserEmailConfirmationToken {
    /// Creates new email confirmation JWT token for a User
    pub fn new(
        wallet: Address,
        old_email: Option<&serde_email::Email>,
        email: &serde_email::Email,
        lifetime: std::time::Duration,
        secret: &[u8],
    ) -> Result<Self, anyhow::Error> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &serde_json::json!({
                "wallet": utils::get_checksum_address(&wallet),
                "oldEmail": old_email,
                "email": email,
                "exp": (Utc::now() + lifetime).timestamp(),
            }),
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .map_err(anyhow::Error::from)
        .map(|token| Self { token })
    }

    /// Validates that verification email JWT token is valid and not expired. Extracts and returns [`UserEmailUpdateRequest`] struct.
    pub fn verify(&self, secret: &[u8]) -> Result<UserEmailUpdateRequest, anyhow::Error> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());

        let token_data = jsonwebtoken::decode::<UserEmailUpdateRequest>(
            &self.token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )?;

        Ok(token_data.claims)
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDbConfig {
    pub base_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendEmailRequest {
    pub kind: SendEmailRequestKind,
    pub from: EmailFrom,
    pub subject: String,
    pub to: serde_email::Email,
    pub verification_url: url::Url,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendEmailRequestKind {
    EmailVerification,
    EmailChange,
}

impl SendEmailRequestKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::EmailChange => "email_change",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EmailFrom {
    pub email: serde_email::Email,
    pub name: String,
}

/// This type represents a wrapped serializable version of [`Cid`]
#[derive(Debug, Clone, PartialEq)]
pub struct WrappedCid(pub Cid);

impl WrappedCid {
    /// Creates [`WrappedCid`] from ref string
    pub fn new(cid: &str) -> anyhow::Result<Self> {
        Cid::from_str(cid)
            .map_err(|_| anyhow::anyhow!("Not a valid Cid"))
            .map(WrappedCid)
    }
}

impl Display for WrappedCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for WrappedCid {
    fn deserialize<D>(deserializer: D) -> Result<WrappedCid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cid_text = <String as Deserialize>::deserialize(deserializer)?;

        Cid::from_str(&cid_text)
            .map(WrappedCid)
            .map_err(|e| de::Error::custom(format!("Failed to deserialize CID: {e:?}")))
    }
}

impl Serialize for WrappedCid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl From<(Address, SBTDbEntry)> for SBTInfo {
    fn from((address, value): (Address, SBTDbEntry)) -> Self {
        Self {
            address,
            name: value.name,
            issued_at_block: value.issued_at_block,
        }
    }
}

impl From<SBTInfo> for (Address, SBTDbEntry) {
    fn from(value: SBTInfo) -> Self {
        (
            value.address,
            SBTDbEntry {
                name: value.name,
                issued_at_block: value.issued_at_block,
            },
        )
    }
}

impl From<(BatchId, Address, RewardDbEntry)> for RewardInfo {
    fn from((id, wallet, value): (BatchId, Address, RewardDbEntry)) -> Self {
        Self {
            id,
            grantor: value.grantor,
            wallet,
            amount: value.amount,
            timestamp: value.timestamp,
            event_name: value.event_name,
            region: value.region,
            community: value.community,
            pseudo: value.pseudo,
            status: value.status,
        }
    }
}

impl From<RewardInfo> for (BatchId, Address, RewardDbEntry) {
    fn from(value: RewardInfo) -> Self {
        (
            value.id,
            value.wallet,
            RewardDbEntry {
                grantor: value.grantor,
                amount: value.amount,
                timestamp: value.timestamp,
                event_name: value.event_name,
                region: value.region,
                community: value.community,
                pseudo: value.pseudo,
                status: value.status,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ethereum_types::Address;
    use hex::ToHex;
    use serde_email::Email;
    use std::time::Duration;

    use super::{
        SessionTokenKind, UpdateRewardRequest, UpdateUserSBTRequest, UserDbEntry, UserProfile,
        UserProfileStatus, WrappedCid,
    };
    use crate::common::{CompletionToken, RawSessionToken, SBTDbEntry, SBTInfo, User};

    #[test]
    fn test_de_update_reward_req() {
        let _ = serde_json::from_str::<UpdateRewardRequest>(
            r#"{
                "claim": {
                    "blockNumber": 10,
                    "wallet": "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99",
                    "id": 1
                },
                "token": "some_token"
            }"#,
        )
        .unwrap();

        let _ = serde_json::from_str::<UpdateRewardRequest>(
            r#"{
                "revert": {
                    "blockNumber": 20,
                    "wallet": "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99",
                    "id": 2
                },
                "token": "some_token"
            }"#,
        )
        .unwrap();

        let _ = serde_json::from_str::<UpdateRewardRequest>(
            r#"{
                "revert": {
                    "blockNumber": 30,
                    "id": 3
                },
                "token": "some_token"
            }"#,
        )
        .unwrap();

        let _ = serde_json::from_str::<UpdateRewardRequest>(
            r#"{
                "grant": {
                    "grantor": "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99",
                    "wallet": "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99",
                    "id": 4,
                    "amount": "1000000",
                    "eventName": "test",
                    "region": "US",
                    "timestamp": 1731661821
                },
                "token": "some_token"
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn test_de_update_user_sbt_req() {
        let _ = serde_json::from_str::<UpdateUserSBTRequest>(
            r#"{
                "wallet": "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99",
                "address": "0x2d41b52C0683bed2C43727521493246256bD5B02",
                "issuedAtBlock": 1000,
                "name": "HumanSBT",
                "token": "some_token"
            }"#,
        )
        .unwrap();

        let _ = serde_json::from_str::<UpdateUserSBTRequest>(
            r#"{
                "wallet": "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99",
                "address": "0x2d41b52C0683bed2C43727521493246256bD5B02",
                "token": "some_token"
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn test_de_user_db_entry() {
        assert!(serde_json::from_str::<UserDbEntry>(
            r#"{
                "wallet": "0x0000000000000000000000000000000000000000",
                "0": "1"
            }"#
        )
        .unwrap()
        .sbts
        .into_iter()
        .map(SBTInfo::from)
        .collect::<Vec<_>>()
        .is_empty(),);

        let mut sbts = serde_json::from_str::<UserDbEntry>(
            r#"{
                "wallet": "0x0000000000000000000000000000000000000000",
                "0": 1,
                "sbts": {
                    "0x0000000000000000000000000000000000001234": {
                        "name": "Test1",
                        "issuedAtBlock": 1
                    },
                    "0x0000000000000000000000000000000000001235": {
                        "name": "Test2",
                        "issuedAtBlock": 2
                    }                
                },
                "test": "value"
            }"#,
        )
        .unwrap()
        .sbts
        .into_iter()
        .map(SBTInfo::from)
        .collect::<Vec<_>>();

        sbts.sort_by(|l, r| l.address.cmp(&r.address));

        assert_eq!(
            sbts,
            vec![
                SBTInfo {
                    address: "0x0000000000000000000000000000000000001234"
                        .parse()
                        .unwrap(),
                    name: "Test1".to_owned(),
                    issued_at_block: 1,
                },
                SBTInfo {
                    address: "0x0000000000000000000000000000000000001235"
                        .parse()
                        .unwrap(),
                    name: "Test2".to_owned(),
                    issued_at_block: 2,
                }
            ]
        );
    }

    #[test]
    fn test_ser_user_db_entry() {
        assert_eq!(
            serde_json::to_string(&UserDbEntry {
                wallet: default_user_wallet(),
                quiz_solved: None,
                blocked_until: None,
                profile: None,
                sbts: Default::default()
            })
            .unwrap()
            .as_str(),
            r#"{"wallet":"0x0000000000000000000000000000000000000000"}"#
        );

        assert_eq!(
            serde_json::to_string(&UserDbEntry {
                wallet: default_user_wallet(),
                quiz_solved: None,
                blocked_until: None,
                profile: None,
                sbts: vec![SBTInfo {
                    address: "0x0000000000000000000000000000000000001234"
                        .parse()
                        .unwrap(),
                    name: "Test1".to_owned(),
                    issued_at_block: 1,
                }]
                .into_iter()
                .map(<(Address, SBTDbEntry)>::from)
                .collect()
            })
            .unwrap()
            .as_str(),
            r#"{"wallet":"0x0000000000000000000000000000000000000000","sbts":{"0x0000000000000000000000000000000000001234":{"name":"Test1","issuedAtBlock":1}}}"#
        );
    }

    #[test]
    fn test_session_token() {
        let now = Utc::now().timestamp_millis() as u64;
        let wallet = Address::random().encode_hex::<String>();
        let token = RawSessionToken {
            kind: SessionTokenKind::Wallet {
                checksum_wallet: wallet.clone(),
            },
            expires_at: now,
        };

        assert_eq!(
            serde_json::to_string(&token).unwrap(),
            format!(r#"{{"wallet":"{wallet}","expiresAt":{now}}}"#)
        );

        assert_matches::assert_matches!(
            serde_json::from_str::<RawSessionToken>(
                r#"{"wallet":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","expiresAt":1000}"#
            )
            .unwrap(),
            RawSessionToken {
                kind: SessionTokenKind::Wallet { checksum_wallet: _ },
                expires_at: _
            }
        );

        let token = RawSessionToken {
            kind: SessionTokenKind::Internal {},
            expires_at: now,
        };

        assert_eq!(
            serde_json::to_string(&token).unwrap(),
            format!(r#"{{"expiresAt":{now}}}"#)
        );

        assert_matches::assert_matches!(
            serde_json::from_str::<RawSessionToken>(r#"{"expiresAt":1000}"#).unwrap(),
            RawSessionToken {
                kind: SessionTokenKind::Internal {},
                expires_at: _
            }
        );
    }

    #[test]
    fn test_de_raw_user_profile() {
        serde_json::from_str::<UserDbEntry>(
            r#"{
            "quizSolved": true,
            "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
            "profile": {
                "name": "test user name",
                "role": "test role",
                "email": "test@test.com",
                "telegram": "@telegram",
                "twitter": "@twitter",
                "bio": "some test bio",
                "avatar": "http://test.com"    
            }
          }"#,
        )
        .unwrap();
    }

    #[test]
    fn test_de_user_profile() {
        assert_matches::assert_matches!(
            serde_json::from_str::<User>(
                r#"
                    {
                        "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
                        "profile": {
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
            Ok(User {
                status: UserProfileStatus::Blocked {
                    blocked_until: 100000
                },
                ..
            })
        );

        assert_matches::assert_matches!(
            serde_json::from_str::<User>(
                r#"
                    {
                        "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
                        "profile": {
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
            Ok(User {
                status: UserProfileStatus::Incomplete {
                    quiz_solved: false,
                    finished_profile: false,
                },
                ..
            })
        );

        assert_matches::assert_matches!(
            serde_json::from_str::<User>(
                r#"
                    {
                        "wallet": "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
                        "profile": {
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
            Ok(User {
                status: UserProfileStatus::Complete(CompletionToken { token }),
                ..
            }) if token.as_str() == "some_verification_token"
        );
    }

    #[test]
    fn test_user_profile_completion() {
        struct TestCase {
            title: &'static str,
            input: User,
            expected: bool,
        }

        let test_cases = [
            TestCase {
                title: "User profile is completed",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(test_user_profile()),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: true,
            },
            TestCase {
                title: "User profile is not completed (missed bio)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(UserProfile {
                            bio: None,
                            ..test_user_profile()
                        }),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (missed name)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(UserProfile {
                            name: None,
                            ..test_user_profile()
                        }),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (missed role)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(UserProfile {
                            role: None,
                            ..test_user_profile()
                        }),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (missed avatar)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(UserProfile {
                            avatar: None,
                            ..test_user_profile()
                        }),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (quiz not solved)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(false),
                        blocked_until: None,
                        profile: Some(test_user_profile()),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (blocked)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: Some(
                            (Utc::now() + Duration::from_secs(300)).timestamp_millis() as u64,
                        ),
                        profile: Some(UserProfile {
                            bio: None,
                            ..test_user_profile()
                        }),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (invalid secret)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(test_user_profile()),
                        sbts: Default::default(),
                    },
                    Utc::now() + Duration::from_secs(300),
                    "unknown_secret".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "User profile is not completed (expired token)",
                input: User::new(
                    UserDbEntry {
                        wallet: default_user_wallet(),
                        quiz_solved: Some(true),
                        blocked_until: None,
                        profile: Some(test_user_profile()),
                        sbts: Default::default(),
                    },
                    Utc::now() - Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .unwrap(),
                expected: false,
            },
        ];

        for (
            i,
            TestCase {
                title,
                input,
                expected,
            },
        ) in test_cases.into_iter().enumerate()
        {
            assert_eq!(
                input.is_complete("test".as_bytes()),
                expected,
                "Test case #{i} '{title}' failed!"
            );
        }
    }

    #[test]
    fn test_cid() {
        let _ = WrappedCid::new("QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA2").unwrap();
        assert!(WrappedCid::new("QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA23").is_err());
        let _ =
            WrappedCid::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap();
        assert!(
            WrappedCid::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzd1").is_err()
        );
    }

    fn default_user_wallet() -> Address {
        Address::from_low_u64_le(0)
    }

    fn test_user_profile() -> UserProfile {
        UserProfile {
            name: Some("test".to_owned()),
            role: Some("test".to_owned()),
            email: Some(Email::from_str("test@test.com").unwrap()),
            telegram: None,
            twitter: None,
            bio: Some("test bio".to_owned()),
            avatar: Some(
                WrappedCid::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
                    .unwrap(),
            ),
        }
    }
}
