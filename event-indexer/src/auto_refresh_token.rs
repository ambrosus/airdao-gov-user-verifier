use chrono::{DateTime, Utc};
use shared::common::SessionToken;
use std::time::Duration;

use airdao_gov_portal_db::session_manager::SessionManager;

const TOKEN_LIFETIME: Duration = Duration::from_secs(3600); // 1 hour

pub struct AutoRefreshToken {
    session_manager: SessionManager,
    token: SessionToken,
    expires_at: DateTime<Utc>,
}

impl AutoRefreshToken {
    pub fn new(session_manager: SessionManager) -> anyhow::Result<Self> {
        let expires_at = Utc::now();
        let token = session_manager.acquire_internal_token_with_lifetime(TOKEN_LIFETIME)?;

        Ok(Self {
            session_manager,
            token,
            expires_at,
        })
    }

    pub fn acquire_token(&mut self) -> anyhow::Result<&SessionToken> {
        if self.expires_at <= Utc::now() + Duration::from_secs(10) {
            self.expires_at = Utc::now();
            self.token = self
                .session_manager
                .acquire_internal_token_with_lifetime(TOKEN_LIFETIME)?;
        }

        Ok(&self.token)
    }
}
