#![cfg(feature = "enable-integration-tests")]
use airdao_gov_portal_db::users_manager::*;
use assert_matches::assert_matches;
use shared::common::User;
use web3::types::Address;

#[tokio::test]
async fn test_register_user() -> Result<(), anyhow::Error> {
    let mongo_config = mongo_client::MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        collection: "Users".to_owned(),
        request_timeout: 10_000,
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
        .register_user(&User {
            wallet: addr_1,
            email: Some("test@test.com".try_into()?),
            ..Default::default()
        })
        .await?;

    // Verify that same wallet can't be registered twice
    assert_matches!(
        users_manager
            .register_user(&User {
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
            .register_user(&User {
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
