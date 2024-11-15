use ethereum_types::Address;
use serde::Deserialize;

use airdao_gov_portal_db::session_manager::{SessionConfig, SessionManager};
use shared::common::{
    BatchId, RewardInfo, SBTInfo, UpdateRewardKind, UpdateRewardRequest, UpdateSBTKind,
    UpdateUserSBTRequest,
};

use crate::auto_refresh_token::AutoRefreshToken;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GovDbConfig {
    /// Session tokens configuration to allow access to database
    pub session: SessionConfig,
    /// DB service request maximum timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
    pub url: String,
}

fn default_request_timeout() -> u64 {
    10
}

pub struct GovDbProvider {
    config: GovDbConfig,
    auto_refresh_token: AutoRefreshToken,
    client: reqwest::Client,
}

impl GovDbProvider {
    pub fn new(config: GovDbConfig) -> anyhow::Result<Self> {
        let auto_refresh_token =
            AutoRefreshToken::new(SessionManager::new(config.session.clone()))?;

        Ok(Self {
            client: reqwest::Client::builder()
                .pool_max_idle_per_host(0)
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .build()?,
            config,
            auto_refresh_token,
        })
    }

    pub async fn upsert_user_sbt(
        &mut self,
        wallet: Address,
        sbt: SBTInfo,
    ) -> anyhow::Result<axum::Json<()>> {
        let token = self.auto_refresh_token.acquire_token()?.clone();

        let bytes = self
            .client
            .post([&self.config.url, "update-user-sbt"].concat())
            .json(&UpdateUserSBTRequest {
                wallet,
                token,
                kind: UpdateSBTKind::Upsert(sbt),
            })
            .send()
            .await?
            .bytes()
            .await?;

        let Ok(json) = axum::Json::<()>::from_bytes(&bytes) else {
            match String::from_utf8(bytes.to_vec()) {
                Ok(text) => anyhow::bail!("{}", text),
                Err(_) => {
                    anyhow::bail!("Unexpected response {bytes:?}")
                }
            }
        };

        Ok(json)
    }

    pub async fn remove_user_sbt(
        &mut self,
        wallet: Address,
        sbt_address: Address,
    ) -> anyhow::Result<axum::Json<()>> {
        let token = self.auto_refresh_token.acquire_token()?.clone();

        let bytes = self
            .client
            .post([&self.config.url, "update-user-sbt"].concat())
            .json(&UpdateUserSBTRequest {
                wallet,
                token,
                kind: UpdateSBTKind::Remove { sbt_address },
            })
            .send()
            .await?
            .bytes()
            .await?;

        let Ok(json) = axum::Json::<()>::from_bytes(&bytes) else {
            match String::from_utf8(bytes.to_vec()) {
                Ok(text) => anyhow::bail!("{}", text),
                Err(_) => {
                    anyhow::bail!("Unexpected response {bytes:?}")
                }
            }
        };

        Ok(json)
    }

    pub async fn insert_reward(&mut self, reward: RewardInfo) -> anyhow::Result<axum::Json<()>> {
        let token = self.auto_refresh_token.acquire_token()?.clone();

        let bytes = self
            .client
            .post([&self.config.url, "update-reward"].concat())
            .json(&UpdateRewardRequest {
                token,
                kind: UpdateRewardKind::Grant(reward),
            })
            .send()
            .await?
            .bytes()
            .await?;

        let Ok(json) = axum::Json::<()>::from_bytes(&bytes) else {
            match String::from_utf8(bytes.to_vec()) {
                Ok(text) => anyhow::bail!("{}", text),
                Err(_) => {
                    anyhow::bail!("Unexpected response {bytes:?}")
                }
            }
        };

        Ok(json)
    }

    pub async fn claim_reward(
        &mut self,
        block_number: u64,
        wallet: Address,
        id: u64,
    ) -> anyhow::Result<axum::Json<()>> {
        let token = self.auto_refresh_token.acquire_token()?.clone();

        let bytes = self
            .client
            .post([&self.config.url, "update-reward"].concat())
            .json(&UpdateRewardRequest {
                token,
                kind: UpdateRewardKind::Claim {
                    block_number,
                    wallet,
                    id: BatchId(id),
                },
            })
            .send()
            .await?
            .bytes()
            .await?;

        let Ok(json) = axum::Json::<()>::from_bytes(&bytes) else {
            match String::from_utf8(bytes.to_vec()) {
                Ok(text) => anyhow::bail!("{}", text),
                Err(_) => {
                    anyhow::bail!("Unexpected response {bytes:?}")
                }
            }
        };

        Ok(json)
    }

    pub async fn revert_reward(
        &mut self,
        block_number: u64,
        id: u64,
    ) -> anyhow::Result<axum::Json<()>> {
        let token = self.auto_refresh_token.acquire_token()?.clone();

        let bytes = self
            .client
            .post([&self.config.url, "update-reward"].concat())
            .json(&UpdateRewardRequest {
                token,
                kind: UpdateRewardKind::Revert {
                    block_number,
                    id: BatchId(id),
                },
            })
            .send()
            .await?
            .bytes()
            .await?;

        let Ok(json) = axum::Json::<()>::from_bytes(&bytes) else {
            match String::from_utf8(bytes.to_vec()) {
                Ok(text) => anyhow::bail!("{}", text),
                Err(_) => {
                    anyhow::bail!("Unexpected response {bytes:?}")
                }
            }
        };

        Ok(json)
    }
}
