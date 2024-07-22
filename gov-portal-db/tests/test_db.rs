#![cfg(feature = "enable-integration-tests")]

use airdao_gov_portal_db::{
    quiz::{Quiz, QuizAnswer, QuizConfig},
    users_manager::{EmailVerificationConfig, *},
};
use assert_matches::assert_matches;
use shared::common::{EmailFrom, User, UserProfile, UserProfileStatus, WrappedCid};
use web3::types::Address;

#[tokio::test]
async fn test_server_status() -> Result<(), anyhow::Error> {
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
            moderators: vec![],
        },
    )
    .await?;

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {})
        .await?;

    assert!(users_manager.mongo_client.server_status().await.is_ok());

    users_manager.mongo_client.collection.drop().await?;

    Ok(())
}

#[tokio::test]
async fn test_upsert_user() -> Result<(), anyhow::Error> {
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
            moderators: vec![],
        },
    )
    .await?;

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {})
        .await?;

    let addr_1 = Address::from_low_u64_le(1);
    let addr_2 = Address::from_low_u64_le(2);

    users_manager
        .upsert_user(addr_1, "test@test.com".try_into()?)
        .await?;

    // Verify that same wallet & email can't be registered twice
    assert_matches!(
        users_manager
            .upsert_user(addr_1, "test@test.com".try_into()?)
            .await,
        Err(error::Error::UserAlreadyExist)
    );

    // Verify that same email can't be registered twice
    assert_matches!(
        users_manager
            .upsert_user(addr_2, "test@test.com".try_into()?)
            .await,
        Err(error::Error::UserAlreadyExist)
    );

    // Verify that email can be updated
    users_manager
        .upsert_user(addr_1, "test1@test.com".try_into()?)
        .await?;

    users_manager.mongo_client.collection.drop().await?;

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

    let moderators = vec![
        Address::from_low_u64_le(1_234_567),
        Address::from_low_u64_le(1_234_568),
        Address::from_low_u64_le(1_234_569),
    ];

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
                moderators,
            },
        )
        .await?,
    );

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {})
        .await?;

    futures_util::future::join_all((1u64..=9).map(|i| {
        let users_manager = users_manager.clone();

        async move {
            let wallet = Address::from_low_u64_le(i);
            users_manager
                .upsert_user(wallet, format!("test{i}@test.com").try_into().unwrap())
                .await
        }
    }))
    .await;

    assert_matches!(
        users_manager
            .get_users_by_wallets(&Address::from_low_u64_le(0), &[])
            .await,
        Err(error::Error::Unauthorized)
    );

    assert_eq!(
        users_manager
            .get_users_by_wallets(&Address::from_low_u64_le(1_234_567), &[])
            .await
            .and_then(|users| users
                .into_iter()
                .map(|user| Ok(user.profile.and_then(|profile| profile.email)))
                .collect::<Result<Vec<_>, _>>())
            .unwrap(),
        vec![]
    );

    assert_eq!(
        users_manager
            .get_users_by_wallets(
                &Address::from_low_u64_le(1_234_568),
                &[
                    Address::from_low_u64_le(11),
                    Address::from_low_u64_le(1),
                    Address::from_low_u64_le(2),
                    Address::from_low_u64_le(8),
                    Address::from_low_u64_le(9),
                    Address::from_low_u64_le(3),
                    Address::from_low_u64_le(10),
                ]
            )
            .await
            .and_then(|users| {
                users
                    .into_iter()
                    .map(|user| Ok(user.profile.and_then(|profile| profile.email)))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap(),
        vec![
            Some("test1@test.com".parse().unwrap()),
            Some("test2@test.com".parse().unwrap()),
            Some("test3@test.com".parse().unwrap()),
            Some("test8@test.com".parse().unwrap()),
            Some("test9@test.com".parse().unwrap())
        ]
    );

    users_manager.mongo_client.collection.drop().await?;

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
            moderators: vec![],
        },
    )
    .await?;

    users_manager
        .mongo_client
        .collection
        .delete_many(bson::doc! {})
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

    let addr_1 = Address::from_low_u64_le(1);

    users_manager
        .upsert_user(addr_1, "test@test.com".try_into()?)
        .await?;

    // Verify that newly registered user has incomplete profile status with not solved quiz
    assert_matches!(
        users_manager.get_user_by_wallet(addr_1).await,
        Ok(User {
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
        Ok(User {
            status: UserProfileStatus::Incomplete {
                quiz_solved: true,
                finished_profile: false
            },
            ..
        })
    );

    users_manager
        .update_user_profile(
            addr_1,
            UserProfile {
                name: Some("some name".to_owned()),
                role: Some("some role".to_owned()),
                bio: Some("some bio".to_owned()),
                avatar: Some(WrappedCid::new(
                    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                )?),
                ..Default::default()
            },
        )
        .await?;

    // Verify that newly registered user has complete profile status with solved quiz
    assert_matches!(
        users_manager.get_user_by_wallet(addr_1).await,
        Ok(User {
            status: UserProfileStatus::Complete(_),
            ..
        })
    );

    users_manager.mongo_client.collection.drop().await?;

    Ok(())
}
