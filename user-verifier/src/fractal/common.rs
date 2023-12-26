use serde::Deserialize;
use shared::common::{OAuthToken, TokenLifetime};

#[derive(Deserialize, Debug)]
pub struct TokenDetails {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    #[serde(flatten)]
    pub lifetime: TokenLifetime,
}

impl From<TokenDetails> for OAuthToken {
    fn from(token: TokenDetails) -> Self {
        Self {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at: token.lifetime.expires_at(),
        }
    }
}
