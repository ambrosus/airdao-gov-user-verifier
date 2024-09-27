#![cfg(feature = "enable-integration-tests")]
use assert_matches::assert_matches;
use ethereum_types::U64;
use ethers::utils::parse_ether;
use ethers_providers::{Provider, Ws};
use std::{str::FromStr, sync::Arc};
use web3::{
    signing::Key,
    types::{BlockNumber, TransactionRequest},
};

use shared::tests::*;

use event_indexer::event_listener::{EventListener, GovEvent, GovEventNotification};

#[tokio::test]
async fn test_rewards_contract() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    let owner = web3::signing::SecretKeyRef::from(&owner_secret);

    let wallets_secret = [
        // Account #16 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "ea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0",
        )?,
        // Account #17 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd",
        )?,
        // Account #18 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
        )?,
        // Account #19 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
        )?,
    ];

    let wallets = wallets_secret
        .iter()
        .map(web3::signing::SecretKeyRef::from)
        .collect::<Vec<_>>();

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;

    let web3_client = web3::Web3::new(http);

    let rewards_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("../../artifacts/RewardDistributionContract.json"),
        (),
        &owner_secret,
    )
    .await?;

    let rewards_contract_addr = rewards_contract.address();

    let _ = web3_client
        .eth()
        .send_transaction(TransactionRequest {
            from: owner.address(),
            to: Some(rewards_contract_addr),
            gas: None,
            gas_price: None,
            value: Some(parse_ether("1")?),
            data: None,
            nonce: None,
            condition: None,
            ..Default::default()
        })
        .await?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<GovEventNotification>();
    let start_block = web3_client.eth().block_number().await?.as_u64();

    let listener_handle = tokio::spawn(async move {
        let provider = Arc::new(Provider::<Ws>::connect("ws://127.0.0.1:8545").await?);
        let listener = EventListener::new(
            [(
                "RewardDistributionContract".to_owned(),
                rewards_contract_addr,
            )]
            .into_iter()
            .collect(),
            provider,
            start_block,
        )?;

        listener.start(tx).await
    });

    signed_call(
        &rewards_contract,
        "distributeRewards",
        (
            wallets
                .iter()
                .map(|wallet| wallet.address())
                .collect::<Vec<_>>(),
            wallets
                .iter()
                .map(|_| ethereum_types::U256::one())
                .collect::<Vec<_>>(),
            "Rewards".to_owned(),
            "NA".to_owned(),
            "TestCommunity".to_owned(),
            "".to_owned(),
        ),
        None,
        &owner_secret,
    )
    .await?;

    let mut events = Vec::with_capacity(wallets.len());
    let received = rx.recv_many(&mut events, wallets.len()).await;
    let rewards_id = events.first().unwrap().block_number;

    assert_eq!(received, wallets.len());
    assert_matches!(
        events
            .into_iter()
            .map(|notification| notification.event)
            .collect::<Vec<_>>()
            .as_slice(),
        &[
            GovEvent::Reward(_),
            GovEvent::Reward(_),
            GovEvent::Reward(_),
            GovEvent::Reward(_),
        ]
    );

    let tx_receipt = signed_call(
        &rewards_contract,
        "claimRewards",
        rewards_id,
        None,
        &wallets_secret[0],
    )
    .await?;

    assert_matches!(
        rx.recv().await.map(|notification| notification.event),
        Some(GovEvent::ClaimReward(wallet, id)) if wallet == wallets[0].address() && id == rewards_id
    );

    // Verify that rewards were acquired after claim
    assert_eq!(
        web3_client
            .eth()
            .balance(
                wallets[0].address(),
                tx_receipt
                    .block_number
                    .and_then(|block| block.checked_sub(U64::one()))
                    .map(BlockNumber::Number)
            )
            .await?
            .checked_sub(transaction_cost(&tx_receipt).unwrap_or_default())
            .and_then(|value| value.checked_add(ethereum_types::U256::one()))
            .unwrap_or_default(),
        web3_client
            .eth()
            .balance(wallets[0].address(), None)
            .await?
    );

    // Verify that contract balance changes
    assert_eq!(
        web3_client
            .eth()
            .balance(
                rewards_contract_addr,
                tx_receipt
                    .block_number
                    .and_then(|block| block.checked_sub(U64::one()))
                    .map(BlockNumber::Number)
            )
            .await?
            .checked_sub(ethereum_types::U256::one())
            .unwrap_or_default(),
        web3_client
            .eth()
            .balance(rewards_contract_addr, None)
            .await?
    );

    // Double claim not possible
    assert!(signed_call(
        &rewards_contract,
        "claimRewards",
        rewards_id,
        None,
        &wallets_secret[0],
    )
    .await
    .is_err());

    signed_call(
        &rewards_contract,
        "revertRewards",
        rewards_id,
        None,
        &owner_secret,
    )
    .await?;

    assert_matches!(
        rx.recv().await.map(|notification| notification.event),
        Some(GovEvent::RevertReward(id)) if id == rewards_id
    );

    // Unable to claim reverted rewards
    assert!(signed_call(
        &rewards_contract,
        "claimRewards",
        rewards_id,
        None,
        &wallets_secret[1],
    )
    .await
    .is_err());

    listener_handle.abort();

    Ok(())
}
