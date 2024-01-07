use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use ethereum_types::Address;
use serde::Deserialize;
use shared::common::{RawSessionToken, SessionToken, WalletSignedMessage};
use tokio::time::Duration;

#[derive(Clone, Debug)]
pub struct SessionManager {
    config: SessionConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionConfig {
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    lifetime: Duration,
    secret: String,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self { config }
    }

    pub fn acquire_token(&self, encoded_message: &str) -> Result<SessionToken, anyhow::Error> {
        let decoded = general_purpose::STANDARD
            .decode(encoded_message)
            .map_err(|e| {
                anyhow::Error::msg(format!(
                    "Failed to deserialize base64 encoded message {e:?}"
                ))
            })?;

        let signed_message =
            serde_json::from_slice::<WalletSignedMessage>(&decoded).map_err(|e| {
                anyhow::Error::msg(format!("Failed to deserialize wallet signed message {e:?}"))
            })?;

        shared::utils::recover_eth_address(signed_message)
            .and_then(|wallet| {
                SessionToken::new(
                    RawSessionToken {
                        checksum_wallet: shared::utils::get_checksum_address(&wallet),
                        expires_at: (Utc::now() + self.config.lifetime).timestamp_millis() as u64,
                    },
                    self.config.secret.as_bytes(),
                )
            })
            .map_err(|e| anyhow::Error::msg(format!("Failed to generate JWT token. Error: {}", e)))
    }

    pub fn verify_token(&self, token: &SessionToken) -> Result<Address, anyhow::Error> {
        let wallet = <[u8; 20]>::try_from(
            hex::decode(token.verify(self.config.secret.as_bytes())?)?.as_slice(),
        )?;

        Ok(ethereum_types::Address::from(&wallet))
    }
}

#[cfg(test)]
mod tests {
    use super::SessionManager;

    #[test]
    fn test_acquire_token() {
        let session_manager = SessionManager::new(super::SessionConfig {
            lifetime: tokio::time::Duration::from_secs(180),
            secret: "TestSecretForJWT".to_owned(),
        });

        session_manager.acquire_token("eyJtc2ciOiI1NDY1NzM3NDIwNGQ2NTczNzM2MTY3NjUiLCJzaWduIjoiM2E2NjUyOTBlZjEyMTAxNjE5OGEzZjI2ODA5NzY0ZGE0ODQzNzg3NWRjNTY1YmYwY2FhY2Q4OWFhYjMzYmM3MDBjMGIwOWE1ZDdiYjI2MmFkZmNkODEwOGI5NjNkZGVhYTJhNmZiNzFhYTRlYjU5OTIxMWY4M2E4NTIyNzY4MzAxYyJ9").unwrap();
    }
}
