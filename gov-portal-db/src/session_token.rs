use chrono::Utc;
use ethereum_types::Address;
use serde::Deserialize;
use shared::common::{RawSessionToken, SessionToken, WalletSignedMessage};
use std::str::FromStr;
use tokio::time::Duration;

#[derive(Clone, Debug)]
pub struct SessionManager {
    pub config: SessionConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionConfig {
    /// Session lifetime in seconds
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub lifetime: Duration,
    /// Secret phrase used to generate and verify session JWT tokens
    pub secret: String,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Acquires a session JWT token to get an access to MongoDB for an eligible user who has proven
    /// his access to a wallet by signing a messgae
    pub fn acquire_token(&self, encoded_message: &str) -> Result<SessionToken, anyhow::Error> {
        let signed_message = WalletSignedMessage::from_str(encoded_message)?;

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

    /// Verifies session JWT token and extracts owning user wallet address
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
