use chrono::{DateTime, Utc};
use shared::common::SessionToken;
use std::time::Duration;

use airdao_gov_portal_db::session_manager::SessionManager;

pub struct AutoRefreshToken {
    session_manager: SessionManager,
    token: SessionToken,
    expires_at: DateTime<Utc>,
}

impl AutoRefreshToken {
    pub fn new(session_manager: SessionManager) -> anyhow::Result<Self> {
        let expires_at = Utc::now() + session_manager.config.lifetime;
        let token = session_manager
            .acquire_internal_token_with_lifetime(session_manager.config.lifetime)?;

        Ok(Self {
            session_manager,
            token,
            expires_at,
        })
    }

    pub fn acquire_token(&mut self) -> anyhow::Result<&SessionToken> {
        let now = Utc::now();
        if self.expires_at <= now + Duration::from_secs(10) {
            self.expires_at = now + self.session_manager.config.lifetime;
            self.token = self
                .session_manager
                .acquire_internal_token_with_lifetime(self.session_manager.config.lifetime)?;
        }

        Ok(&self.token)
    }
}
