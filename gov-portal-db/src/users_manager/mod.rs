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
use serde::{ser::SerializeSeq, Deserialize, Serialize, Serializer};
use tokio::time::Duration;

use shared::{
    common::{
        EmailFrom, RawUserProfile, SendEmailRequest, UserEmailConfirmationToken, UserInfo,
        UserProfile,
    },
    utils,
};

use mongo_client::{MongoClient, MongoConfig};

const MONGO_DUPLICATION_ERROR: i32 = 11000;

/// Users manager's [`UsersManager`] settings
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
    pub email_verification: EmailVerificationConfig,
    pub moderators: Vec<Address>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EmailVerificationConfig {
    /// Mailer service base url to send emails from AirDao Gov Portal
    pub mailer_base_url: url::Url,
    #[serde(deserialize_with = "utils::de_secs_duration")]
    pub send_timeout: std::time::Duration,
    pub template_url: String,
    pub from: EmailFrom,
    pub subject: String,
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
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum QuizResult {
    Solved(u64, u64),
    Failed(u64, u64, DateTime<Utc>),
    AlreadySolved,
}

impl Serialize for QuizResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Solved(valid_answers, required_answers) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(valid_answers)?;
                seq.serialize_element(required_answers)?;
                seq.end()
            }
            Self::Failed(valid_answers, required_answers, blocked_until) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(valid_answers)?;
                seq.serialize_element(required_answers)?;
                seq.serialize_element(&blocked_until.timestamp_millis())?;
                seq.end()
            }
            Self::AlreadySolved => serializer.serialize_none(),
        }
    }
}

/// User profiles manager which provides read/write access to user profile data stored MongoDB
pub struct UsersManager {
    pub mongo_client: MongoClient,
    pub mailer_client: reqwest::Client,
    pub mailer_url: url::Url,
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
            mailer_client: reqwest::Client::new(),
            mailer_url: config
                .email_verification
                .mailer_base_url
                .join("/send-email")?,
            config,
        })
    }

    /// Registers new user by writing verified [`UserInfo`] struct to MongoDB, which will be uniquely indexed by
    /// EVM-like wallet address [`Address`] and user email [`serde_email::Email`].
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

    /// Searches for a user profile within MongoDB by provided EVM-like address [`Address`] and returns [`UserProfile`]
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

    /// Searches for multiple user profiles within MongoDB by provided EVM-like address [`Address`] list and returns [`Vec<UserProfile>`]
    pub async fn get_users_by_wallets(
        &self,
        requestor: &Address,
        wallets: &[Address],
    ) -> Result<Vec<UserProfile>, error::Error> {
        if !self
            .config
            .moderators
            .iter()
            .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }

        if wallets.is_empty() {
            return Ok(vec![]);
        }

        let filter = doc! {
            "wallet": {
                "$in": bson::to_bson(wallets)?
            },
        };

        let find_options = FindOptions::builder()
            .max_time(self.mongo_client.req_timeout)
            .build();

        let res = tokio::time::timeout(self.mongo_client.req_timeout, async {
            let mut stream = self.mongo_client.find(filter, find_options).await?;
            let mut profiles = Vec::with_capacity(wallets.len());
            loop {
                if profiles.len() == wallets.len() {
                    break;
                }

                if let Ok(Some(doc)) = stream.try_next().await {
                    let profile =
                        bson::from_document::<RawUserProfile>(doc).map_err(error::Error::from)?;
                    profiles.push(profile);
                } else {
                    break;
                }
            }
            Ok(profiles)
        })
        .await?;

        tracing::debug!("Get users by wallets ({wallets:?}) result: {res:?}");

        res.and_then(|raw_profiles| {
            raw_profiles
                .into_iter()
                .map(|raw_profile| {
                    UserProfile::new(
                        raw_profile,
                        Utc::now() + self.config.lifetime,
                        self.config.secret.as_bytes(),
                    )
                    .map_err(error::Error::from)
                })
                .collect::<Result<_, _>>()
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
            "$set": bson::to_bson(&RawUserProfile::from(user))?
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
        quiz_result: &QuizResult,
    ) -> Result<(), error::Error> {
        let update = match quiz_result {
            QuizResult::Solved(..) => {
                doc! {
                    "$set": bson::to_bson(&RawUserProfile {
                        quiz_solved: Some(true),
                        blocked_until: None,
                        info: UserInfo {
                            wallet,
                            name: None,
                            role: None,
                            old_email: None,
                            email: None,
                            telegram: None,
                            twitter: None,
                            bio: None,
                            avatar: None
                        },
                    })?
                }
            }
            QuizResult::Failed(_, _, block_until) => {
                doc! {
                    "$set": bson::to_bson(&RawUserProfile {
                        quiz_solved: Some(false),
                        blocked_until: Some(block_until.timestamp_millis() as u64),
                        info: UserInfo {
                            wallet,
                            name: None,
                            role: None,
                            old_email: None,
                            email: None,
                            telegram: None,
                            twitter: None,
                            bio: None,
                            avatar: None
                        },
                    })?
                }
            }
            QuizResult::AlreadySolved => return Ok(()),
        };

        let query = doc! {
            "wallet": bson::to_bson(&wallet)?,
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

    /// Acquires email confirmation JWT token [`UserEmailConfirmationToken`] for a pair of EVM-like wallet address [`Address`] and
    /// user email [`serde_email::Email`]. Should be used to set or update email in user profile.
    /// JWT token will contain EVM-like wallet address [`Address`] and user email [`serde_email::Email`] which could be used
    /// to create [`UserInfo`] struct out of it.
    pub fn acquire_email_confirmation_token(
        &self,
        wallet: Address,
        old_email: Option<&serde_email::Email>,
        email: &serde_email::Email,
    ) -> Result<UserEmailConfirmationToken, anyhow::Error> {
        UserEmailConfirmationToken::new(
            wallet,
            old_email,
            email,
            self.config.lifetime,
            self.config.secret.as_bytes(),
        )
        .map_err(|e| anyhow::Error::msg(format!("Failed to generate JWT token. Error: {}", e)))
    }

    /// Verifies JWT token [`UserEmailConfirmationToken`] and extracts EVM-like wallet address [`Address`]
    /// and user email [`serde_email::Email`] to create [`UserInfo`] struct with extracted fields set.
    pub fn verify_email_confirmation_token(
        &self,
        token: &UserEmailConfirmationToken,
    ) -> Result<UserInfo, anyhow::Error> {
        let user = token.verify(self.config.secret.as_bytes())?;

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

        Ok(())
    }

    pub async fn send_email_verification(&self, req: SendEmailRequest) -> Result<(), String> {
        tracing::debug!(
            "Send verification request {req:?} to mailer service (url: {url})",
            url = self.mailer_url
        );

        match tokio::time::timeout(
            self.config.email_verification.send_timeout,
            self.mailer_client
                .post(self.mailer_url.as_str())
                .json(&req)
                .send(),
        )
        .await
        {
            Ok(Ok(res)) => res
                .text()
                .await
                .map_err(|e| format!("Failed to get response. Error: {e:?}"))
                .and_then(utils::parse_json_response),
            Ok(Err(e)) => Err(format!("Failed to send verification email. Error: {e:?}")),
            Err(_) => Err(format!(
                "Send verification email timeout ({timeout:?}).",
                timeout = self.config.email_verification.send_timeout
            )),
        }
    }

    /// Checks if email already being used by some user
    pub async fn is_email_being_used(
        &self,
        email: &serde_email::Email,
    ) -> Result<bool, anyhow::Error> {
        let filter = doc! {
            "email": bson::to_bson(&email)?,
        };

        let find_options = FindOptions::builder()
            .max_time(self.mongo_client.req_timeout)
            .build();

        Ok(tokio::time::timeout(self.mongo_client.req_timeout, async {
            self.mongo_client
                .find(filter, find_options)
                .await?
                .try_next()
                .await
        })
        .await??
        .is_some())
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
    use assert_matches::assert_matches;
    use chrono::{NaiveDateTime, TimeZone, Utc};

    use super::{QuizResult, UsersManagerConfig};

    #[test]
    fn test_ser_quiz_result() {
        assert_matches!(
            serde_json::to_string(&QuizResult::Solved(4, 5)).as_deref(),
            Ok("[4,5]")
        );

        assert_matches!(
            serde_json::to_string(&QuizResult::Failed(
                3,
                5,
                Utc.from_utc_datetime(
                    &NaiveDateTime::from_timestamp_millis(1708997209002).unwrap()
                )
            ))
            .as_deref(),
            Ok("[3,5,1708997209002]")
        );

        assert_matches!(
            serde_json::to_string(&QuizResult::AlreadySolved).as_deref(),
            Ok("null")
        );
    }

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
                    "bioMinLength": 2
                },
                "emailVerification": {
                    "mailerBaseUrl": "http://localhost:10002",
                    "sendTimeout": 10,
                    "templateUrl": "https://airdao.io/gov-portal/email-verification?token={{VERIFICATION_TOKEN}}",
                    "from": {
                        "name": "AirDAO Gov Portal",
                        "email": "gwg@airdao.io"
                    },
                    "subject": "Complete Your Governor Email Verification"
                },
                "moderators": ["0xc0ffee254729296a45a3885639AC7E10F9d54979"]
            }
        "#,
        )
        .unwrap();
    }
}
