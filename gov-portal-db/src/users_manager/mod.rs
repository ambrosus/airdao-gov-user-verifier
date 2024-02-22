pub mod error;
pub mod mongo_client;

use bson::doc;
use chrono::{DateTime, Utc};
use ethereum_types::Address;
use futures_util::TryStreamExt;
use mongodb::{
    error::{Error as MongoError, ErrorKind as MongoErrorKind, WriteError, WriteFailure},
    options::{FindOptions, UpdateOptions},
    results::UpdateResult,
};
use serde::Deserialize;
use tokio::time::Duration;

use shared::common::{
    RawUserProfile, RawUserRegistrationToken, UserInfo, UserProfile, UserRegistrationToken,
};

use mongo_client::{MongoClient, MongoConfig};

const MONGO_DUPLICATION_ERROR: i32 = 11000;

/// Users manager's [`UsersManager`] settings for JWT registration token and user profile attributes verification
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UsersManagerConfig {
    /// Lifetime for which user verification JWT token will be valid
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub lifetime: Duration,
    /// Secret being used to create user verification JWT token
    pub secret: String,
    /// User profile attributes verification settings
    pub user_profile_attributes: UserProfileAttributes,
}

/// Contains settings to verify user profile [`User`] attributes
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserProfileAttributes {
    pub name_max_length: usize,
    pub name_min_length: usize,
    pub role_max_length: usize,
    pub role_min_length: usize,
    pub email_max_length: usize,
    pub email_min_length: usize,
    pub telegram_max_length: usize,
    pub twitter_max_length: usize,
    pub bio_max_length: usize,
    pub bio_min_length: usize,
    pub avatar_url_max_length: usize,
    pub avatar_url_min_length: usize,
}

impl Default for UserProfileAttributes {
    fn default() -> Self {
        Self {
            name_max_length: 64,
            name_min_length: 2,
            role_max_length: 50,
            role_min_length: 2,
            email_max_length: 64,
            email_min_length: 5, // length("a@a.a")
            telegram_max_length: 32,
            twitter_max_length: 32,
            bio_max_length: 250,
            bio_min_length: 2,
            avatar_url_max_length: 250,
            avatar_url_min_length: 7, // length("a://a.a")
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum QuizResult {
    Solved,
    Failed(DateTime<Utc>),
}

/// User profiles manager which provides read/write access to user profile data stored MongoDB
pub struct UsersManager {
    pub mongo_client: MongoClient,
    pub config: UsersManagerConfig,
}

impl UsersManager {
    /// Constructs [`UsersManager`] with provided confuguration
    pub async fn new(
        mongo_config: &MongoConfig,
        config: UsersManagerConfig,
    ) -> anyhow::Result<Self> {
        let mongo_client = MongoClient::new(mongo_config).await?;

        Ok(Self {
            mongo_client,
            config,
        })
    }

    /// Registers new user by writing [`User`] struct to MongoDB, which will be uniquely indexed by EVM-like wallet address [`Address`].
    /// Input [`User`] struct is verified for correctness.
    pub async fn register_user(&self, user: &UserInfo) -> Result<(), error::Error> {
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
    pub async fn get_user_by_wallet(&self, wallet: Address) -> Result<UserProfile, error::Error> {
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
        .and_then(|doc| bson::from_document::<RawUserProfile>(doc).map_err(error::Error::from));

        tracing::debug!("Get user by wallet ({wallet}) result: {res:?}");

        res.and_then(|raw_profile| {
            UserProfile::new(
                raw_profile,
                Utc::now() + self.config.lifetime,
                self.config.secret.as_bytes(),
            )
            .map_err(error::Error::from)
        })
    }

    /// Updates user profile stored in MongoDB by updated [`User`] struct. Input [`User`] struct is verified for correctness.
    pub async fn update_user(&self, user: UserInfo) -> Result<(), error::Error> {
        self.verify_user(&user)?;

        let wallet = user.wallet;

        let query = doc! {
            "wallet": bson::to_bson(&wallet)?,
        };

        let update = doc! {
            "$set": bson::to_bson(&RawUserProfile {
                info: user,
                ..Default::default()
            })?
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

        tracing::debug!("Update user by wallet ({wallet}) result: {res:?}");

        res
    }

    /// Updates user profile stored in MongoDB by updated [`User`] struct. Input [`User`] struct is verified for correctness.
    pub async fn update_user_quiz_result(
        &self,
        wallet: Address,
        quiz_result: QuizResult,
    ) -> Result<(), error::Error> {
        let query = doc! {
            "wallet": bson::to_bson(&wallet)?,
        };

        let update = match quiz_result {
            QuizResult::Solved => {
                doc! {
                    "$set": bson::to_bson(&RawUserProfile {
                        quiz_solved: Some(true),
                        ..Default::default()
                    })?
                }
            }
            QuizResult::Failed(block_until) => {
                doc! {
                    "$set": bson::to_bson(&RawUserProfile {
                        quiz_solved: Some(false),
                        blocked_until: Some(block_until.timestamp_millis() as u64),
                        ..Default::default()
                    })?
                }
            }
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

        tracing::debug!("Update user by wallet ({wallet}) result: {res:?}");

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
                expires_at: (Utc::now() + self.config.lifetime).timestamp_millis() as u64,
            },
            self.config.secret.as_bytes(),
        )
        .map_err(|e| anyhow::Error::msg(format!("Failed to generate JWT token. Error: {}", e)))
    }

    /// Verifies JWT token [`UserRegistrationToken`] and extracts EVM-like wallet address [`Address`]
    /// and user email [`serde_email::Email`] to create user profile [`User`] struct filled with extracted fields.
    pub fn verify_registration_token(
        &self,
        token: &UserRegistrationToken,
    ) -> Result<UserInfo, anyhow::Error> {
        let user = UserInfo::try_from(token.verify(self.config.secret.as_bytes())?)?;

        self.verify_user(&user)?;

        Ok(user)
    }

    /// Verifies user profile [`User`] struct fields for correctness
    fn verify_user(&self, user: &UserInfo) -> Result<(), error::Error> {
        if user.name.as_ref().is_some_and(|value| {
            value.len() < self.config.user_profile_attributes.name_min_length
                || value.len() > self.config.user_profile_attributes.name_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Name doesn't met requirements (min: {}, max: {})",
                self.config.user_profile_attributes.name_min_length,
                self.config.user_profile_attributes.name_max_length
            )));
        }

        if user.role.as_ref().is_some_and(|value| {
            value.len() < self.config.user_profile_attributes.role_min_length
                || value.len() > self.config.user_profile_attributes.role_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Role doesn't met requirements (min: {}, max: {})",
                self.config.user_profile_attributes.role_min_length,
                self.config.user_profile_attributes.role_max_length
            )));
        }

        if user.email.as_ref().is_some_and(|value| {
            value.as_str().len() < self.config.user_profile_attributes.email_min_length
                || value.as_str().len() > self.config.user_profile_attributes.email_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Email doesn't met requirements (min: {}, max: {})",
                self.config.user_profile_attributes.email_min_length,
                self.config.user_profile_attributes.email_max_length
            )));
        }

        if user.telegram.as_ref().is_some_and(|value| {
            value.len() > self.config.user_profile_attributes.telegram_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Telegram handle too long (max: {})",
                self.config.user_profile_attributes.telegram_max_length
            )));
        }

        if user.twitter.as_ref().is_some_and(|value| {
            value.len() > self.config.user_profile_attributes.twitter_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Twitter identifier too long (max: {})",
                self.config.user_profile_attributes.twitter_max_length
            )));
        }

        if user.bio.as_ref().is_some_and(|value| {
            value.len() < self.config.user_profile_attributes.bio_min_length
                || value.len() > self.config.user_profile_attributes.bio_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Bio doesn't met requirements (min: {}, max: {})",
                self.config.user_profile_attributes.bio_min_length,
                self.config.user_profile_attributes.bio_max_length
            )));
        }

        if user.avatar.as_ref().is_some_and(|value| {
            value.as_str().len() < self.config.user_profile_attributes.avatar_url_min_length
                || value.as_str().len() > self.config.user_profile_attributes.avatar_url_max_length
        }) {
            return Err(error::Error::InvalidInput(format!(
                "Avatar URL doesn't met requirements (min: {}, max: {})",
                self.config.user_profile_attributes.avatar_url_min_length,
                self.config.user_profile_attributes.avatar_url_max_length
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
    use super::UsersManagerConfig;

    #[test]
    fn test_user_registration_config() {
        serde_json::from_str::<UsersManagerConfig>(
            r#"
            {
                "secret": "some_secret",
                "lifetime": 600,
                "userProfileAttributes": {
                    "nameMaxLength": 64,
                    "nameMinLength": 2,
                    "roleMaxLength": 50,
                    "roleMinLength": 2,
                    "emailMaxLength": 64,
                    "emailMinLength": 5,
                    "telegramMaxLength": 32,
                    "twitterMaxLength": 32,
                    "bioMaxLength": 250,
                    "bioMinLength": 2,
                    "avatarUrlMaxLength": 250,
                    "avatarUrlMinLength": 7
                }
            }
        "#,
        )
        .unwrap();
    }
}
