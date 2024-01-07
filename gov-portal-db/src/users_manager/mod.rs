pub mod error;
pub mod mongo_client;

use bson::doc;
use chrono::Utc;
use ethereum_types::Address;
use futures_util::TryStreamExt;
use mongodb::{
    error::{Error as MongoError, ErrorKind as MongoErrorKind, WriteError, WriteFailure},
    options::FindOptions,
};
use serde::Deserialize;
use tokio::time::Duration;

use shared::common::{RawUserRegistrationToken, User, UserRegistrationToken};

use crate::config::AppConfig;
use mongo_client::MongoClient;

#[derive(Deserialize, Debug, Clone)]
pub struct UserRegistrationConfig {
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    lifetime: Duration,
    secret: String,
}

pub struct UsersManager {
    pub mongo_client: MongoClient,
    pub registration_config: UserRegistrationConfig,
}

impl UsersManager {
    pub async fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let mongo_client = MongoClient::init(&config.mongo).await?;

        Ok(Self {
            mongo_client,
            registration_config: config.registration.clone(),
        })
    }

    pub async fn register_user(&self, user: &User) -> Result<(), error::Error> {
        let user_doc = bson::to_document(&user)?;

        match self.mongo_client.insert_one(user_doc, None).await {
            Ok(_) => Ok(()),
            Err(MongoError { kind, .. }) if is_key_duplication_error(&kind) => {
                Err(error::Error::UserAlreadyExist)
            }
            Err(e) => Err(error::Error::from(e)),
        }
    }

    pub async fn get_user_by_wallet(&self, wallet: Address) -> Result<User, error::Error> {
        let filter = doc! {
            "wallet": bson::to_bson(&wallet)?,
        };

        let find_options = FindOptions::builder()
            .max_time(self.mongo_client.req_timeout)
            .build();

        let res = tokio::time::timeout(self.mongo_client.req_timeout, async {
            self.mongo_client
                .find(filter, find_options)
                .await?
                .try_next()
                .await
        })
        .await??
        .ok_or(error::Error::UserNotFound)
        .and_then(|doc| bson::from_document::<User>(doc).map_err(error::Error::from));

        tracing::debug!("Get user by wallet ({wallet}) result: {res:?}");

        res
    }

    pub fn acquire_registration_token(
        &self,
        wallet: Address,
        email: serde_email::Email,
    ) -> Result<UserRegistrationToken, anyhow::Error> {
        UserRegistrationToken::new(
            RawUserRegistrationToken {
                checksum_wallet: shared::utils::get_checksum_address(&wallet),
                email,
                expires_at: (Utc::now() + self.registration_config.lifetime).timestamp_millis()
                    as u64,
            },
            self.registration_config.secret.as_bytes(),
        )
        .map_err(|e| anyhow::Error::msg(format!("Failed to generate JWT token. Error: {}", e)))
    }

    pub fn verify_registration_token(
        &self,
        token: &UserRegistrationToken,
    ) -> Result<User, anyhow::Error> {
        User::try_from(token.verify(self.registration_config.secret.as_bytes())?)
    }
}

fn is_key_duplication_error(error_kind: &MongoErrorKind) -> bool {
    matches!(
        error_kind,
        MongoErrorKind::Write(WriteFailure::WriteError(WriteError { code: 11000, .. }))
    )
}
