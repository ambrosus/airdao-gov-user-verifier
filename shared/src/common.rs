use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ethabi::{encode, Address, ParamType, Token};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::decode_sbt_request;

/// Minimum time required before oauth2 token expires in minutes
static OAUTH_TOKEN_MINIMUM_LIFETIME: i64 = 5;

#[derive(Deserialize, Debug)]
pub struct VerifyAccountRequest {
    pub wallet: ethabi::Address,
    #[serde(flatten)]
    pub token: TokenKind,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum VerifyAccountResponse {
    Approved(ApprovedResponse),
    Pending(PendingResponse),
}

/// Signed response for a fractal user with approved face verification
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ApprovedResponse {
    pub msg: String,
}

/// Response for a fractal user whos face verification is pending for final decision
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct PendingResponse {
    pub token: OAuthToken,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SignedSBTRequest {
    #[serde(rename = "d")]
    pub data: String,
    pub v: u8,
    pub r: String,
    pub s: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SBTRequest {
    pub caller: Address,
    pub user_id: String,
    pub req_expires_at: u64,
    pub sbt_expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub wallet: Address,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionToken {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawSessionToken {
    #[serde(rename = "wallet")]
    pub checksum_wallet: String,
    pub expires_at: u64,
}

impl RawSessionToken {
    pub fn verify(&self) -> bool {
        self.expires_at > Utc::now().timestamp_millis() as u64
    }
}

impl SessionToken {
    pub fn new(token: RawSessionToken, secret: &[u8]) -> Result<Self, anyhow::Error> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &token,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .map_err(anyhow::Error::from)
        .map(|token| SessionToken { token })
    }

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
            println!("{:?}", token_data.claims);
            Ok(token_data.claims.checksum_wallet)
        }
    }
}

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

#[derive(Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum TokenKind {
    AuthorizationCode {
        auth_code: String,
        redirect_uri: String,
    },
    OAuth {
        token: OAuthToken,
        redirect_uri: String,
    },
}

#[derive(Debug, PartialEq, Clone)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

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
    pub fn expires_at(&self) -> DateTime<Utc> {
        Utc.timestamp_nanos((self.created_at + self.expires_in) as i64 * 1_000_000_000)
    }
}

impl OAuthToken {
    pub fn requires_refresh(&self) -> bool {
        Utc::now() + Duration::minutes(OAUTH_TOKEN_MINIMUM_LIFETIME) >= self.expires_at
    }
}
