use ethereum_types::Address;
use reqwest::Client;
use serde::Deserialize;

use shared::common::{OAuthToken, TokenKind};

use super::{common::TokenDetails, user_profile::*};
use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct FractalClient {
    inner_client: Client,
    config: FractalConfig,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FractalConfig {
    pub request_token_url: String,
    pub request_user_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedUser {
    pub user_id: UserId,
    pub token: OAuthToken,
    pub status: UserStatus,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct UserStatus {
    pub uniqueness: VerificationStatus,
    pub basic: VerificationStatus,
}

impl FractalClient {
    pub fn new(config: FractalConfig) -> Result<Self, AppError> {
        let inner_client = Client::builder().pool_max_idle_per_host(0).build()?;

        Ok(Self {
            inner_client,
            config,
        })
    }

    pub async fn fetch_and_verify_user(
        &self,
        fractal_token: TokenKind,
        wallet_address: Address,
    ) -> Result<VerifiedUser, AppError> {
        let mut oauth_token = match fractal_token {
            TokenKind::AuthorizationCode {
                auth_code,
                redirect_uri,
                ..
            } => self.acquire_oauth_token(&auth_code, &redirect_uri).await?,
            TokenKind::OAuth { token, .. } => token,
        };

        if oauth_token.requires_refresh() {
            oauth_token = self.refresh_oauth_token(oauth_token).await?;
        }

        tracing::debug!("Acquired user token: {oauth_token:?}");

        let fetched_res = self
            .inner_client
            .get(&self.config.request_user_url)
            .bearer_auth(&oauth_token.access_token)
            .send()
            .await?
            .json::<UserProfile>()
            .await
            .map_err(AppError::from);

        match fetched_res {
            Ok(user) if !user.is_wallet_matches(wallet_address) => {
                Err(AppError::WalletMatchFailure)
            }
            Ok(mut user) => {
                tracing::debug!("Fetched raw user: {user:?}");

                Ok(VerifiedUser {
                    status: UserStatus {
                        uniqueness: user.get_status(&[
                            VerificationLevel::Uniqueness,
                            // VerificationLevel::Liveness, this causes long verification process on Fractal side
                            VerificationLevel::WalletEth,
                        ]),
                        basic: user
                            .get_status(&[VerificationLevel::Basic, VerificationLevel::Liveness]),
                    },
                    user_id: user.uid,
                    token: oauth_token,
                })
            }
            Err(e) => Err(AppError::FractalError(format!(
                "Unable to fetch user. Error: {:?}",
                e
            ))),
        }
    }

    async fn acquire_oauth_token(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthToken, AppError> {
        let params: [(&str, &str); 5] = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];

        let data = self
            .inner_client
            .post(&self.config.request_token_url)
            .form(&params)
            .send()
            .await?
            .text()
            .await?;

        tracing::debug!("Acquired raw fractal token response: {data}");

        match serde_json::from_str::<TokenDetails>(&data) {
            Ok(token) if token.token_type.as_str() == "Bearer" => Ok(OAuthToken::from(token)),
            Ok(token) => Err(format!("Unsupported token type {:?}", token).into()),
            Err(_) => Err(format!("Failed to parse token response {:?}", data).into()),
        }
    }

    async fn refresh_oauth_token(&self, oauth_token: OAuthToken) -> Result<OAuthToken, AppError> {
        tracing::debug!("Refresh for OAuthToken: {oauth_token:?}");

        let params: [(&str, &str); 4] = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("refresh_token", &oauth_token.refresh_token),
            ("grant_type", "refresh_token"),
        ];

        let data = self
            .inner_client
            .post(&self.config.request_token_url)
            .form(&params)
            .send()
            .await?
            .text()
            .await?;

        match serde_json::from_str::<TokenDetails>(&data) {
            Ok(token) if token.token_type.as_str() == "Bearer" => Ok(OAuthToken::from(token)),
            Ok(token) => Err(format!("Unsupported token type {:?}", token).into()),
            Err(_) => Err(format!("Failed to parse token response {:?}", data).into()),
        }
    }
}
