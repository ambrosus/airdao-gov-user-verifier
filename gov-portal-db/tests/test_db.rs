#![cfg(feature = "enable-integration-tests")]
use std::str::FromStr;

use airdao_gov_portal_db::{
    quiz::{Quiz, QuizAnswer, QuizConfig},
    users_manager::*,
};
use assert_matches::assert_matches;
use shared::common::{UserInfo, UserProfile, UserProfileStatus};
use web3::types::Address;

#[tokio::test]
async fn test_register_user() -> Result<(), anyhow::Error> {
    let mongo_config = mongo_client::MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        collection: "Users".to_owned(),
        request_timeout: 10,
    };

    let registration_config = UserRegistrationConfig {
        secret: "IntegrationTestRegistrationSecretForJWT".to_owned(),
        lifetime: std::time::Duration::from_secs(600),
        user_profile_attributes: UserProfileAttributes {
            name_max_length: 64,
            role_max_length: 50,
            email_max_length: 64,
            telegram_max_length: 32,
            twitter_max_length: 32,
            bio_max_length: 250,
            avatar_url_max_length: 250,
        },
    };

    let users_manager = UsersManager::new(&mongo_config, registration_config).await?;

    let addr_1 = Address::from_low_u64_le(0);
    let addr_2 = Address::from_low_u64_le(1);

    users_manager
        .register_user(&UserInfo {
            wallet: addr_1,
            email: Some("test@test.com".try_into()?),
            ..Default::default()
        })
        .await?;

    // Verify that same wallet can't be registered twice
    assert_matches!(
        users_manager
            .register_user(&UserInfo {
                wallet: addr_1,
                email: Some("test1@test.com".try_into()?),
                ..Default::default()
            })
            .await,
        Err(error::Error::UserAlreadyExist)
    );

    // Verify that same email can't be registered twice
    assert_matches!(
        users_manager
            .register_user(&UserInfo {
                wallet: addr_2,
                email: Some("test@test.com".try_into()?),
                ..Default::default()
            })
            .await,
        Err(error::Error::UserAlreadyExist)
    );

    users_manager.mongo_client.collection.drop(None).await?;

    Ok(())
}

#[tokio::test]
async fn test_complete_profile() -> Result<(), anyhow::Error> {
    let quiz_config = serde_json::from_str::<QuizConfig>(
        r#"
        {
            "failedQuizBlockDuration": 172800,
            "minimumValidAnswersRequired": 1,
            "questions": [
                {
                    "title": "Question 1",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some invalid answer 3", false],
                        ["some valid answer 4", true]
                    ]
                }
            ]
        }
        "#,
    )
    .unwrap();

    let quiz = Quiz {
        config: quiz_config,
    };

    let mongo_config = mongo_client::MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        collection: "Users".to_owned(),
        request_timeout: 10,
    };

    let registration_config = UserRegistrationConfig {
        secret: "IntegrationTestRegistrationSecretForJWT".to_owned(),
        lifetime: std::time::Duration::from_secs(600),
        user_profile_attributes: UserProfileAttributes {
            name_max_length: 64,
            role_max_length: 50,
            email_max_length: 64,
            telegram_max_length: 32,
            twitter_max_length: 32,
            bio_max_length: 250,
            avatar_url_max_length: 250,
        },
    };

    let users_manager = UsersManager::new(&mongo_config, registration_config).await?;

    let quiz_result = quiz.verify_answers(vec![
        serde_json::from_str::<QuizAnswer>(
            r#"{"question": "Question 1", "variant": "some valid answer 3"}"#,
        )
        .unwrap(),
        serde_json::from_str::<QuizAnswer>(
            r#"{"question": "Question 2", "variant": "some valid answer 4"}"#,
        )
        .unwrap(),
    ]);

    assert_matches!(quiz_result, QuizResult::Solved);

    let addr_1 = Address::from_low_u64_le(0);

    users_manager
        .register_user(&UserInfo {
            wallet: addr_1,
            email: Some("test@test.com".try_into()?),
            ..Default::default()
        })
        .await?;

    // Verify that newly registered user has incomplete profile status with not solved quiz
    assert_matches!(
        users_manager.get_user_by_wallet(addr_1).await,
        Ok(UserProfile {
            status: UserProfileStatus::Incomplete {
                quiz_solved: false,
                finished_profile: false
            },
            ..
        })
    );

    users_manager
        .update_user_quiz_result(addr_1, quiz_result)
        .await?;

    // Verify that newly registered user has incomplete profile status with solved quiz
    assert_matches!(
        users_manager.get_user_by_wallet(addr_1).await,
        Ok(UserProfile {
            status: UserProfileStatus::Incomplete {
                quiz_solved: true,
                finished_profile: false
            },
            ..
        })
    );

    users_manager
        .update_user(UserInfo {
            wallet: addr_1,
            name: Some("some name".to_owned()),
            role: Some("some role".to_owned()),
            bio: Some("some bio".to_owned()),
            avatar: Some(url::Url::from_str("http://avatar.link")?),
            ..Default::default()
        })
        .await?;

    // Verify that newly registered user has complete profile status with solved quiz
    assert_matches!(
        users_manager.get_user_by_wallet(addr_1).await,
        Ok(UserProfile {
            status: UserProfileStatus::Complete(_),
            ..
        })
    );

    users_manager.mongo_client.collection.drop(None).await?;

    Ok(())
}
