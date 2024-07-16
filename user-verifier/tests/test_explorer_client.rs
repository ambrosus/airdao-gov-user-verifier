#![cfg(feature = "enable-integration-tests")]
use assert_matches::assert_matches;
use chrono::Utc;
use ethereum_types::Address;

use airdao_gov_user_verifier::explorer_client::{ExplorerClient, ExplorerConfig};

#[tokio::test]
async fn test_find_first_transaction_before() -> Result<(), anyhow::Error> {
    let client = ExplorerClient::new(ExplorerConfig {
        url: "https://explorer-v2-api.ambrosus.io/v2/addresses/".to_owned(),
        timeout: std::time::Duration::from_secs(10),
    })?;

    let wallet = Address::from(
        <[u8; 20]>::try_from(hex::decode("aeE13A8db3e216A364255EFEbA171ce329100876")?).map_err(
            |failed_data| {
                anyhow::format_err!("Failed to deserialize Address from: {failed_data:?}")
            },
        )?,
    );
    let tx = client
        .find_first_transaction_before(wallet, Utc::now())
        .await;
    assert_matches!(tx, Ok(Some(_)));

    Ok(())
}
