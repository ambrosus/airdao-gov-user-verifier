pub mod error;
pub mod mongo_client;

use bson::doc;
use chrono::Utc;
use ethereum_types::Address;
use futures_util::TryStreamExt;
use mongodb::{
    error::{Error as MongoError, ErrorKind as MongoErrorKind, WriteError, WriteFailure},
    options::{FindOptions, UpdateOptions},
    results::UpdateResult,
};
use serde::Deserialize;
use tokio::time::Duration;

use shared::common::{RawUserRegistrationToken, User, UserRegistrationToken};

use crate::config::AppConfig;
use mongo_client::MongoClient;

const MONGO_DUPLICATION_ERROR: i32 = 11000;

/// Users manager's [`UsersManager`] settings for JWT registration token and user profile attributes verification
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserRegistrationConfig {
    /// Lifetime for which JWT registration token will be valid to register new user profile
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    lifetime: Duration,
    /// Secret being used to sign JWT registration token
    secret: String,
    /// User profile attributes verification settings
    user_profile_attributes: UserProfileAttributes,
}

/// Contains settings to verify user profile [`User`] attributes
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserProfileAttributes {
    name_max_length: usize,
    role_max_length: usize,
    email_max_length: usize,
    telegram_max_length: usize,
    twitter_max_length: usize,
    bio_max_length: usize,
}

/// User profiles manager which provides read/write access to user profile data stored MongoDB
pub struct UsersManager {
    pub mongo_client: MongoClient,
    pub registration_config: UserRegistrationConfig,
}

impl UsersManager {
    /// Constructs [`UsersManager`] with provided confuguration
    pub async fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let mongo_client = MongoClient::new(&config.mongo).await?;

        Ok(Self {
            mongo_client,
            registration_config: config.registration.clone(),
        })
    }

    /// Registers new user by writing [`User`] struct to MongoDB, which will be uniquely indexed by EVM-like wallet address [`Address`].
    /// Input [`User`] struct is verified for correctness.
    pub async fn register_user(&self, user: &User) -> Result<(), error::Error> {
        self.verify_user(user)?;

        let user_doc = bson::to_document(&user)?;

        match self.mongo_client.insert_one(user_doc, None).await {
            Ok(_) => Ok(()),
            Err(MongoError { kind, .. }) if is_key_duplication_error(&kind) => {
                Err(error::Error::UserAlreadyExist)
            }
            Err(e) => Err(error::Error::from(e)),
        }
    }

    /// Searches for a user profile within MongoDB by provided EVM-like address [`Address`] and returns [`User`]
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

    /// Updates user profile stored in MongoDB by updated [`User`] struct. Input [`User`] struct is verified for correctness.
    pub async fn update_user(&self, user: User) -> Result<(), error::Error> {
        self.verify_user(&user)?;

        let query = doc! {
            "wallet": bson::to_bson(&user.wallet)?,
        };

        let update = doc! {
            "$set": bson::to_bson(&user)?
        };

        let options = UpdateOptions::builder().upsert(false).build();

        let update_result = tokio::time::timeout(self.mongo_client.req_timeout, async {
            self.mongo_client.update_one(query, update, options).await
        })
        .await?;

        let res = match update_result {
            Ok(UpdateResult { matched_count, .. }) if matched_count > 0 => Ok(()),
            Ok(_) => Err(error::Error::UserNotFound),
            Err(e) => Err(e.into()),
        };

        tracing::debug!("Update user by wallet ({}) result: {res:?}", user.wallet);

        res
    }

    /// Acquires registration JWT token [`UserRegistrationToken`] for a pair of EVM-like wallet address [`Address`] and
    /// user email [`serde_email::Email`]. Should be used to register new user profile.
    /// JWT token will contain EVM-like wallet address [`Address`] and user email [`serde_email::Email`] which could be used
    /// to create [`User`] struct out of it.
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

    /// Verifies JWT token [`UserRegistrationToken`] and extracts EVM-like wallet address [`Address`]
    /// and user email [`serde_email::Email`] to create user profile [`User`] struct filled with extracted fields.
    pub fn verify_registration_token(
        &self,
        token: &UserRegistrationToken,
    ) -> Result<User, anyhow::Error> {
        let user = User::try_from(token.verify(self.registration_config.secret.as_bytes())?)?;

        self.verify_user(&user)?;

        Ok(user)
    }

    /// Verifies user profile [`User`] struct fields for correctness
    fn verify_user(&self, user: &User) -> Result<(), error::Error> {
        if user.name.as_ref().is_some_and(|value| {
            value.len()
                > self
                    .registration_config
                    .user_profile_attributes
                    .name_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Name too long (max: {})",
                self.registration_config
                    .user_profile_attributes
                    .name_max_length
            )));
        }

        if user.role.as_ref().is_some_and(|value| {
            value.len()
                > self
                    .registration_config
                    .user_profile_attributes
                    .role_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Role too long (max: {})",
                self.registration_config
                    .user_profile_attributes
                    .role_max_length
            )));
        }

        if user.email.as_ref().is_some_and(|value| {
            value.as_str().len()
                > self
                    .registration_config
                    .user_profile_attributes
                    .email_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Email too long (max: {})",
                self.registration_config
                    .user_profile_attributes
                    .email_max_length
            )));
        }

        if user.telegram.as_ref().is_some_and(|value| {
            value.len()
                > self
                    .registration_config
                    .user_profile_attributes
                    .telegram_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Telegram handle too long (max: {})",
                self.registration_config
                    .user_profile_attributes
                    .telegram_max_length
            )));
        }

        if user.twitter.as_ref().is_some_and(|value| {
            value.len()
                > self
                    .registration_config
                    .user_profile_attributes
                    .twitter_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Twitter identifier too long (max: {})",
                self.registration_config
                    .user_profile_attributes
                    .twitter_max_length
            )));
        }

        if user.bio.as_ref().is_some_and(|value| {
            value.len()
                > self
                    .registration_config
                    .user_profile_attributes
                    .bio_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Bio too long (max: {})",
                self.registration_config
                    .user_profile_attributes
                    .bio_max_length
            )));
        }

        Ok(())
    }
}

/// Returns true if an input error kind [`MongoErrorKind`] is representing duplication error or false otherwise.
fn is_key_duplication_error(error_kind: &MongoErrorKind) -> bool {
    matches!(
        error_kind,
        MongoErrorKind::Write(WriteFailure::WriteError(WriteError {
            code: MONGO_DUPLICATION_ERROR,
            ..
        }))
    )
}

#[cfg(test)]
mod tests {
    use super::UserRegistrationConfig;

    #[test]
    fn test_user_registration_config() {
        serde_json::from_str::<UserRegistrationConfig>(
            r#"
            {
                "secret": "some_secret",
                "lifetime": 600,
                "userProfileAttributes": {
                    "nameMaxLength": 64,
                    "roleMaxLength": 50,
                    "emailMaxLength": 64,
                    "telegramMaxLength": 32,
                    "twitterMaxLength": 32,
                    "bioMaxLength": 250
                }
            }
        "#,
        )
        .unwrap();
    }
}
