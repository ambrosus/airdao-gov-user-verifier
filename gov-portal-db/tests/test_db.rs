#![cfg(feature = "enable-integration-tests")]

use airdao_gov_portal_db::{
    quiz::{Quiz, QuizAnswer, QuizConfig},
    users_manager::{EmailVerificationConfig, *},
};
use assert_matches::assert_matches;
use shared::common::{EmailFrom, UserInfo, UserProfile, UserProfileStatus, WrappedCid};
use web3::types::Address;

#[tokio::test]
async fn test_register_user() -> Result<(), anyhow::Error> {
    let mongo_config = mongo_client::MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        collection: "Users".to_owned(),
        request_timeout: 10,
    };

    let users_manager = UsersManager::new(
        &mongo_config,
        UsersManagerConfig {
            secret: "IntegrationTestRegistrationSecretForJWT".to_owned(),
            lifetime: std::time::Duration::from_secs(600),
            user_profile_attributes: UserProfileAttributes::default(),
            email_verification: EmailVerificationConfig {
                mailer_base_url: "http://mailer".try_into().unwrap(),
                send_timeout: std::time::Duration::from_secs(10),
                template_url: "https://registration?token={{VERIFICATION_TOKEN}}".to_string(),
                from: EmailFrom {
                    email: "gwg@airdao.io".try_into().unwrap(),
                    name: "AirDAO Gov Portal".to_string(),
                },
                subject: "Complete Your Governor Email Verification".to_string(),
            },
        },
    )
    .await?;

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {}, None)
        .await?;

    let addr_1 = Address::from_low_u64_le(0);
    let addr_2 = Address::from_low_u64_le(1);

    users_manager
        .register_user(&UserInfo {
            wallet: addr_1,
            email: Some("test@test.com".try_into()?),
            ..default_user_info()
        })
        .await?;

    // Verify that same wallet can't be registered twice
    assert_matches!(
        users_manager
            .register_user(&UserInfo {
                wallet: addr_1,
                email: Some("test1@test.com".try_into()?),
                ..default_user_info()
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
                ..default_user_info()
            })
            .await,
        Err(error::Error::UserAlreadyExist)
    );

    users_manager.mongo_client.collection.drop(None).await?;

    Ok(())
}

#[tokio::test]
async fn test_users_endpoint() -> Result<(), anyhow::Error> {
    let mongo_config = mongo_client::MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        collection: "Users".to_owned(),
        request_timeout: 10,
    };

    let users_manager = std::sync::Arc::new(
        UsersManager::new(
            &mongo_config,
            UsersManagerConfig {
                secret: "IntegrationTestRegistrationSecretForJWT".to_owned(),
                lifetime: std::time::Duration::from_secs(600),
                user_profile_attributes: UserProfileAttributes::default(),
                email_verification: EmailVerificationConfig {
                    mailer_base_url: "http://mailer".try_into().unwrap(),
                    send_timeout: std::time::Duration::from_secs(10),
                    template_url: "https://registration?token={{VERIFICATION_TOKEN}}".to_string(),
                    from: EmailFrom {
                        email: "gwg@airdao.io".try_into().unwrap(),
                        name: "AirDAO Gov Portal".to_string(),
                    },
                    subject: "Complete Your Governor Email Verification".to_string(),
                },
            },
        )
        .await?,
    );

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {}, None)
        .await?;

    futures_util::future::join_all((0u64..=8).map(|i| {
        let users_manager = users_manager.clone();

        async move {
            let wallet = Address::from_low_u64_le(i);
            users_manager
                .register_user(&UserInfo {
                    wallet,
                    email: Some(format!("test{i}@test.com").try_into().unwrap()),
                    ..default_user_info()
                })
                .await
        }
    }))
    .await;

    assert_eq!(
        users_manager
            .get_users_by_wallets(&[
                Address::from_low_u64_le(10),
                Address::from_low_u64_le(0),
                Address::from_low_u64_le(1),
                Address::from_low_u64_le(7),
                Address::from_low_u64_le(8),
                Address::from_low_u64_le(2),
                Address::from_low_u64_le(9),
            ])
            .await
            .and_then(|profiles| profiles
                .into_iter()
                .map(|profile| Ok(profile.info.email))
                .collect::<Result<Vec<_>, _>>())
            .unwrap(),
        vec![
            Some("test0@test.com".parse().unwrap()),
            Some("test1@test.com".parse().unwrap()),
            Some("test2@test.com".parse().unwrap()),
            Some("test7@test.com".parse().unwrap()),
            Some("test8@test.com".parse().unwrap())
        ]
    );

    users_manager.mongo_client.collection.drop(None).await?;

    Ok(())
}

#[tokio::test]
async fn test_complete_profile() -> Result<(), anyhow::Error> {
    let quiz_config = serde_json::from_str::<QuizConfig>(
        r#"
        {
            "secret": "IntegrationTestQuizSecretForJWT",
            "numberOfQuizQuestionsShown": {
                "easy": 2,
                "moderate": 1
            },
            "minimumTotalValidAnswersRequired": 2,
            "minimumValidAnswersRequired": {
                "easy": 1,
                "moderate": 1
            },
            "timeToSolve": 300,
            "failedQuizBlockDuration": 172800,
            "questions": [
                {
                    "title": "Question 1",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "difficulty": "moderate",
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

    let users_manager = UsersManager::new(
        &mongo_config,
        UsersManagerConfig {
            secret: "IntegrationTestRegistrationSecretForJWT".to_owned(),
            lifetime: std::time::Duration::from_secs(600),
            user_profile_attributes: UserProfileAttributes::default(),
            email_verification: EmailVerificationConfig {
                mailer_base_url: "http://mailer".try_into().unwrap(),
                send_timeout: std::time::Duration::from_secs(10),
                template_url: "https://registration?token={{VERIFICATION_TOKEN}}".to_string(),
                from: EmailFrom {
                    email: "gwg@airdao.io".try_into().unwrap(),
                    name: "AirDAO Gov Portal".to_string(),
                },
                subject: "Complete Your Governor Email Verification".to_string(),
            },
        },
    )
    .await?;

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {}, None)
        .await?;

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

    assert_matches!(quiz_result, QuizResult::Solved(2, 2));

    let addr_1 = Address::from_low_u64_le(0);

    users_manager
        .register_user(&UserInfo {
            wallet: addr_1,
            email: Some("test@test.com".try_into()?),
            ..default_user_info()
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
        .update_user_quiz_result(addr_1, &quiz_result)
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
            avatar: Some(WrappedCid::new(
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            )?),
            ..default_user_info()
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

fn default_user_info() -> UserInfo {
    UserInfo {
        wallet: Address::default(),
        name: None,
        role: None,
        old_email: None,
        email: None,
        telegram: None,
        twitter: None,
        bio: None,
        avatar: None,
    }
}
