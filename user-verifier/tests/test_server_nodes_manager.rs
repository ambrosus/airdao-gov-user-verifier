#![cfg(feature = "enable-integration-tests")]
use assert_matches::assert_matches;
use std::str::FromStr;
use web3::signing::Key;

use airdao_gov_user_verifier::{
    rpc_node_client::{RpcNodeClient, RpcNodeConfig},
    server_nodes_manager::ServerNodesManager,
    tests::*,
};

// const ERR_NODE_ALREADY_REGISTERED: &str = "Error: VM Exception while processing transaction: reverted with reason string 'node already registered'";

#[tokio::test]
async fn test_node_owner() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    // Account #19 private key from Hardhat local node
    let wallet_secret = web3::signing::SecretKey::from_str(
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    )?;
    let wallet = web3::signing::SecretKeyRef::from(&wallet_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let validator_set_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("./artifacts/ValidatorSet.json"),
        (
            ethereum_types::Address::zero(),
            ethereum_types::U256::zero(),
            ethereum_types::U256::from(32),
        ),
        &owner_secret,
    )
    .await?;

    let lock_keeper_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("./artifacts/LockKeeper.json"),
        (),
        &owner_secret,
    )
    .await?;

    let server_nodes_manager_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("../artifacts/ServerNodes_Manager.json"),
        (
            validator_set_contract.address(), // ValidatorSet
            lock_keeper_contract.address(),   // LockKeeper
            ethereum_types::Address::zero(),  // RewardsBank
            ethereum_types::Address::zero(),  // airBond
            ethereum_types::Address::zero(),  // Treasury
            ethereum_types::U256::zero(),     // _onboardingDelay
            ethereum_types::U256::zero(),     // _unstakeLockTime
            ethereum_types::U256::zero(),     // _minStakeAmount
        ),
        &owner_secret,
    )
    .await?;

    if !has_role(
        &validator_set_contract,
        "STAKING_MANAGER_ROLE",
        server_nodes_manager_contract.address(),
    )
    .await?
    {
        grant_role(
            &validator_set_contract,
            "STAKING_MANAGER_ROLE",
            server_nodes_manager_contract.address(),
            &owner_secret,
        )
        .await?;
    }

    let rpc_node_client = RpcNodeClient::new(RpcNodeConfig {
        url: "http://127.0.0.1:8545".to_owned(),
        request_timeout: std::time::Duration::from_secs(10),
    })?;
    let server_nodes_manager =
        ServerNodesManager::new(server_nodes_manager_contract.address(), rpc_node_client)?;

    // Shouldn't be a node owner
    assert_matches!(
        server_nodes_manager.is_node_owner(wallet.address()).await,
        Ok(false)
    );

    signed_call(
        &server_nodes_manager_contract,
        "newStake",
        (ethereum_types::Address::zero(), wallet.address()),
        Some(ethereum_types::U256::one()),
        &wallet_secret,
    )
    .await?;

    // assert_matches!(
    //     &new_stake_res,
    //     Err(ApiError(web3::Error::Rpc(RPCError { message, .. }))) if message.as_str() == ERR_NODE_ALREADY_REGISTERED,
    //     "newStake failure: {new_stake_res:?}"
    // );

    // Node stake created, but it is still in onboarding list
    assert_matches!(
        server_nodes_manager.is_node_owner(wallet.address()).await,
        Ok(false)
    );

    signed_call(
        &server_nodes_manager_contract,
        "onBlock",
        (),
        None,
        &wallet_secret,
    )
    .await?;

    // Node stake confirmed
    assert_matches!(
        server_nodes_manager.is_node_owner(wallet.address()).await,
        Ok(true)
    );

    signed_call(
        &server_nodes_manager_contract,
        "unstake",
        (ethereum_types::Address::zero(), ethereum_types::U256::one()),
        None,
        &wallet_secret,
    )
    .await?;

    signed_call(
        &server_nodes_manager_contract,
        "onBlock",
        (),
        None,
        &wallet_secret,
    )
    .await?;

    // Unstaked, user is no longer a node owner
    assert_matches!(
        server_nodes_manager.is_node_owner(wallet.address()).await,
        Ok(false)
    );

    Ok(())
}
