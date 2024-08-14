#![cfg(feature = "enable-integration-tests")]
use assert_matches::assert_matches;
use chrono::{DateTime, Duration, Utc};
use ethereum_types::{Address, U256};
use jsonrpc_core::Error as RPCError;
use std::str::FromStr;
use uuid::Uuid;
use web3::{
    contract::{self, Contract, Error::Api as ApiError},
    signing::{Key, SecretKey, SecretKeyRef},
    types::TransactionRequest,
};

use airdao_gov_user_verifier::{signer, tests::*};

const ERR_SBT_EXPIRED_OR_NOT_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'SBT expired or not exist'";
const ERR_SBT_ALREADY_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'This kind of SBT already exist'";

// Account #1 private key from Hardhat local node
const HUMAN_SBT_SIGNER_PRIVATE_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
// Account #2 private key from Hardhat local node
const OG_SBT_SIGNER_PRIVATE_KEY: &str =
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
// Account #3 private key from Hardhat local node
const SNO_SBT_SIGNER_PRIVATE_KEY: &str =
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";

#[tokio::test]
async fn test_roles() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    let signer_private_key = hex::decode(HUMAN_SBT_SIGNER_PRIVATE_KEY)?;
    let signer_secret = web3::signing::SecretKey::from_slice(&signer_private_key)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let issuer_contract = deploy_contract(
        web3_client.eth(),
        include_str!("./artifacts/HumanSBTIssuer.json"),
        (),
        &owner_secret,
    )
    .await?;

    // revoke_role(
    //     &issuer_contract,
    //     "SIGN_PROVIDER_ROLE",
    //     signer.address(),
    //     &owner_secret,
    // )
    // .await?;
    assert!(!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?));
    grant_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("./artifacts/HumanSBT.json"),
        (),
        &owner_secret,
    )
    .await?;

    // revoke_role(
    //     &sbt_contract,
    //     "ISSUER_ROLE",
    //     issuer_contract.address(),
    //     &owner_secret,
    // )
    // .await?;
    assert!(!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?));
    grant_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?);

    Ok(())
}

#[tokio::test]
async fn test_human_sbt() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    let signer_secret =
        web3::signing::SecretKey::from_slice(&hex::decode(HUMAN_SBT_SIGNER_PRIVATE_KEY)?)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);

    // Account #19 private key from Hardhat local node
    let wallet_secret = web3::signing::SecretKey::from_str(
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    )?;
    let wallet = web3::signing::SecretKeyRef::from(&wallet_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let issuer_contract = deploy_contract(
        web3_client.eth(),
        include_str!("./artifacts/HumanSBTIssuer.json"),
        (),
        &owner_secret,
    )
    .await?;

    grant_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("./artifacts/HumanSBT.json"),
        (),
        &owner_secret,
    )
    .await?;

    grant_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?);

    let signer_config = signer::SignerConfig {
        keys: signer::SignerKeys {
            issuer_human_sbt: k256::SecretKey::from_slice(&hex::decode(
                HUMAN_SBT_SIGNER_PRIVATE_KEY,
            )?)?
            .into(),
            issuer_og_sbt: k256::SecretKey::from_slice(&hex::decode(OG_SBT_SIGNER_PRIVATE_KEY)?)?
                .into(),
            issuer_sno_sbt: k256::SecretKey::from_slice(&hex::decode(SNO_SBT_SIGNER_PRIVATE_KEY)?)?
                .into(),
        },
        request_lifetime: std::time::Duration::from_secs(60),
        sbt_lifetime: std::time::Duration::from_secs(3153600000),
        og_eligible_before: get_latest_block_timestamp(web3_client.eth()).await?,
    };

    let req_signer = signer::SBTRequestSigner::new(signer_config);
    let user_id = uuid::Uuid::from_str("01020304-0506-1122-8877-665544332211")?.as_u128();
    let req = req_signer.build_signed_sbt_request(
        wallet.address(),
        user_id,
        get_latest_block_timestamp(web3_client.eth()).await?,
    )?;

    let signed_data = hex::decode(&req.data)?;
    let sig_r: [u8; 32] = hex::decode(&req.r)?.try_into().map_err(|e| {
        anyhow::Error::msg(format!(
            "Signature R data is not 32 bytes length. Error: {e:?}"
        ))
    })?;
    let sig_s: [u8; 32] = hex::decode(&req.s)?.try_into().map_err(|e| {
        anyhow::Error::msg(format!(
            "Signature S data is not 32 bytes length. Error: {e:?}"
        ))
    })?;

    // Try to mint Human SBT
    signed_call(
        &issuer_contract,
        "sbtMint",
        (
            sbt_contract.address(),
            signed_data.clone(),
            req.v,
            sig_r,
            sig_s,
        ),
        None,
        &wallet_secret,
    )
    .await
    .unwrap();
    // Verify that Human SBT can't be minted twice
    let err_already_exist = signed_call(
        &issuer_contract,
        "sbtMint",
        (sbt_contract.address(), signed_data, req.v, sig_r, sig_s),
        None,
        &wallet_secret,
    )
    .await
    .unwrap_err();
    assert_matches!(err_already_exist, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_ALREADY_EXIST);

    // Verify that Human SBT is minted correctly
    let (user_id, _) = gov_sbt_verify(&sbt_contract, wallet.address()).await?;
    assert_eq!(user_id.as_str(), "01020304-0506-1122-8877-665544332211");

    // Try to burn Human SBT
    signed_call(
        &issuer_contract,
        "sbtBurn",
        (sbt_contract.address(), wallet.address()),
        None,
        &owner_secret,
    )
    .await
    .unwrap();

    // Verify that Human SBT doesn't exist anymore
    let err_no_sbt = gov_sbt_verify(&sbt_contract, wallet.address())
        .await
        .unwrap_err();
    assert_matches!(err_no_sbt, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_EXPIRED_OR_NOT_EXIST);

    Ok(())
}

#[tokio::test]
async fn test_og_sbt() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    let signer_secret =
        web3::signing::SecretKey::from_slice(&hex::decode(OG_SBT_SIGNER_PRIVATE_KEY)?)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);

    // Account #19 private key from Hardhat local node
    let wallet_secret = web3::signing::SecretKey::from_str(
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    )?;
    let wallet = web3::signing::SecretKeyRef::from(&wallet_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let tx = TransactionRequest {
        from: wallet.address(),
        to: Some(signer.address()),
        gas: None,
        gas_price: None,
        value: Some(U256::from(1)),
        data: None,
        nonce: None,
        condition: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };

    let tx_hash = web3_client.eth().send_transaction(tx).await?;

    let issuer_contract = deploy_contract(
        web3_client.eth(),
        include_str!("./artifacts/OGSBTIssuer.json"),
        (),
        &owner_secret,
    )
    .await?;

    grant_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("./artifacts/OGSBT.json"),
        (),
        &owner_secret,
    )
    .await?;

    grant_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?);

    let signer_config = signer::SignerConfig {
        keys: signer::SignerKeys {
            issuer_human_sbt: k256::SecretKey::from_slice(&hex::decode(
                HUMAN_SBT_SIGNER_PRIVATE_KEY,
            )?)?
            .into(),
            issuer_og_sbt: k256::SecretKey::from_slice(&hex::decode(OG_SBT_SIGNER_PRIVATE_KEY)?)?
                .into(),
            issuer_sno_sbt: k256::SecretKey::from_slice(&hex::decode(SNO_SBT_SIGNER_PRIVATE_KEY)?)?
                .into(),
        },
        request_lifetime: std::time::Duration::from_secs(60),
        sbt_lifetime: std::time::Duration::from_secs(3153600000),
        og_eligible_before: get_latest_block_timestamp(web3_client.eth()).await?,
    };

    let req_signer = signer::SBTRequestSigner::new(signer_config);
    let req = req_signer.build_signed_og_sbt_request(
        wallet.address(),
        wallet.address(),
        tx_hash,
        get_latest_block_timestamp(web3_client.eth()).await?,
    )?;

    let signed_data = hex::decode(&req.data)?;
    let sig_r: [u8; 32] = hex::decode(&req.r)?.try_into().map_err(|e| {
        anyhow::Error::msg(format!(
            "Signature R data is not 32 bytes length. Error: {e:?}"
        ))
    })?;
    let sig_s: [u8; 32] = hex::decode(&req.s)?.try_into().map_err(|e| {
        anyhow::Error::msg(format!(
            "Signature S data is not 32 bytes length. Error: {e:?}"
        ))
    })?;

    // Try to mint OG SBT
    signed_call(
        &issuer_contract,
        "sbtMint",
        (
            sbt_contract.address(),
            signed_data.clone(),
            req.v,
            sig_r,
            sig_s,
        ),
        None,
        &wallet_secret,
    )
    .await
    .unwrap();
    // Verify that OG SBT can't be minted twice
    let err_already_exist = signed_call(
        &issuer_contract,
        "sbtMint",
        (sbt_contract.address(), signed_data, req.v, sig_r, sig_s),
        None,
        &wallet_secret,
    )
    .await
    .unwrap_err();
    assert_matches!(err_already_exist, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_ALREADY_EXIST);

    // Verify that OG SBT is minted correctly
    let issued_at = sbt_verify(&sbt_contract, wallet.address()).await?;
    assert_ne!(issued_at, DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    // Try to burn OG SBT
    signed_call(
        &issuer_contract,
        "sbtBurn",
        (sbt_contract.address(), wallet.address()),
        None,
        &owner_secret,
    )
    .await
    .unwrap();

    // Verify that OG SBT doesn't exist anymore
    let zero_date = sbt_verify(&sbt_contract, wallet.address()).await?;
    assert_eq!(zero_date, DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    Ok(())
}

#[tokio::test]
async fn test_sno_sbt() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;
    // let owner = web3::signing::SecretKeyRef::from(&owner_secret);

    let signer_secret =
        web3::signing::SecretKey::from_slice(&hex::decode(SNO_SBT_SIGNER_PRIVATE_KEY)?)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);

    let node_wallets_secret = vec![
        // Account #18 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
        )?,
        // Account #19 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
        )?,
    ];
    let node_wallets = node_wallets_secret
        .iter()
        .map(web3::signing::SecretKeyRef::from)
        .collect::<Vec<_>>();

    let wallets_secret = vec![
        // Account #16 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "ea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0",
        )?,
        // Account #17 private key from Hardhat local node
        web3::signing::SecretKey::from_str(
            "689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd",
        )?,
    ];

    let wallets = wallets_secret
        .iter()
        .map(web3::signing::SecretKeyRef::from)
        .collect::<Vec<_>>();

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let validator_set_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("../artifacts/ValidatorSet.json"),
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
            U256::zero(),                     // _onboardingDelay
            U256::zero(),                     // _unstakeLockTime
            U256::zero(),                     // _minStakeAmount
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

    for ((wallet, wallet_secret), (node_wallet, node_wallet_secret)) in wallets
        .iter()
        .zip(&wallets_secret)
        .zip(node_wallets.iter().zip(&node_wallets_secret))
    {
        signed_call(
            &server_nodes_manager_contract,
            "newStake",
            (node_wallet.address(), wallet.address()),
            Some(U256::one()),
            wallet_secret,
        )
        .await?;

        signed_call(
            &server_nodes_manager_contract,
            "onBlock",
            (),
            None,
            &owner_secret,
        )
        .await?;

        // Set miner address to be able to call `ValidatorSet::process()` method
        let _ = hardhat_set_coinbase(web3_client.transport(), node_wallet.address()).await?;

        signed_call(
            &validator_set_contract,
            "process",
            (),
            None,
            node_wallet_secret,
        )
        .await?;

        assert_matches!(
            validator_set_contract
                .query::<(U256, Address, bool), _, _, _>(
                    "stakes",
                    node_wallet.address(),
                    None,
                    contract::Options::default(),
                    None,
                )
                .await,
            Ok((staked, _, _)) if staked == U256::one()
        );
    }

    let issuer_contract = deploy_contract(
        web3_client.eth(),
        include_str!("./artifacts/SNOSBTIssuer.json"),
        (),
        &owner_secret,
    )
    .await?;

    grant_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = deploy_upgradeable_contract(
        web3_client.eth(),
        include_str!("./artifacts/SNOSBT.json"),
        (),
        &owner_secret,
    )
    .await?;

    grant_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?);

    let signer_config = signer::SignerConfig {
        keys: signer::SignerKeys {
            issuer_human_sbt: k256::SecretKey::from_slice(&hex::decode(
                HUMAN_SBT_SIGNER_PRIVATE_KEY,
            )?)?
            .into(),
            issuer_og_sbt: k256::SecretKey::from_slice(&hex::decode(OG_SBT_SIGNER_PRIVATE_KEY)?)?
                .into(),
            issuer_sno_sbt: k256::SecretKey::from_slice(&hex::decode(SNO_SBT_SIGNER_PRIVATE_KEY)?)?
                .into(),
        },
        request_lifetime: std::time::Duration::from_secs(60),
        sbt_lifetime: std::time::Duration::from_secs(3153600000),
        og_eligible_before: get_latest_block_timestamp(web3_client.eth()).await?,
    };

    let req_signer = signer::SBTRequestSigner::new(signer_config);

    // Try to mint SNO SBT
    mint_sno_sbt(
        &web3_client,
        &req_signer,
        &wallets[0],
        &wallets_secret[0],
        &wallets[0],
        &sbt_contract,
        &server_nodes_manager_contract,
        &issuer_contract,
    )
    .await?;

    // Verify that SNO SBT can't be minted twice
    let err_already_exist = mint_sno_sbt(
        &web3_client,
        &req_signer,
        &wallets[0],
        &wallets_secret[0],
        &wallets[0],
        &sbt_contract,
        &server_nodes_manager_contract,
        &issuer_contract,
    )
    .await
    .unwrap_err();
    assert!(err_already_exist
        .to_string()
        .contains(ERR_SBT_ALREADY_EXIST));

    // Verify that SNO SBT is minted correctly
    assert_ne!(
        sbt_verify(&sbt_contract, wallets[0].address()).await?,
        DateTime::<Utc>::from_timestamp(0, 0).unwrap()
    );

    // Unstake to remove node from validators list
    signed_call(
        &server_nodes_manager_contract,
        "unstake",
        (node_wallets[0].address(), U256::one()),
        None,
        &wallets_secret[0],
    )
    .await?;

    // Verify that SNO SBT is not valid anymore
    assert_eq!(
        sbt_verify(&sbt_contract, wallets[0].address()).await?,
        DateTime::<Utc>::from_timestamp(0, 0).unwrap()
    );

    // Try to re-mint SNO SBT with different SNO wallet
    mint_sno_sbt(
        &web3_client,
        &req_signer,
        &wallets[0],
        &wallets_secret[0],
        &wallets[1],
        &sbt_contract,
        &server_nodes_manager_contract,
        &issuer_contract,
    )
    .await?;

    // Verify that SNO SBT is re-minted correctly
    assert_ne!(
        sbt_verify(&sbt_contract, wallets[0].address()).await?,
        DateTime::<Utc>::from_timestamp(0, 0).unwrap()
    );

    // Set max time since last reward to zero to fail SNO SBT verification
    signed_call(
        &sbt_contract,
        "editMaxTimeSinceLastReward",
        U256::zero(),
        None,
        &owner_secret,
    )
    .await
    .unwrap();

    // Verify that SNO SBT is not valid anymore
    assert_eq!(
        sbt_verify(&sbt_contract, wallets[0].address()).await?,
        DateTime::<Utc>::from_timestamp(0, 0).unwrap()
    );

    // Try to burn SNO SBT
    signed_call(
        &issuer_contract,
        "sbtBurn",
        (sbt_contract.address(), wallets[0].address()),
        None,
        &owner_secret,
    )
    .await
    .unwrap();

    // Verify that SNO SBT doesn't exist anymore
    assert_matches!(
        sbt_exists(&sbt_contract, wallets[0].address()).await,
        Ok(false)
    );

    Ok(())
}

pub async fn gov_sbt_verify<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    wallet_addr: ethabi::Address,
) -> contract::Result<(String, DateTime<Utc>)> {
    let (user_id, seconds_till_expiration) = contract
        .query::<(u128, u64), _, _, _>(
            "sbtVerify",
            wallet_addr,
            wallet_addr,
            contract::Options::default(),
            None,
        )
        .await?;

    Ok((
        Uuid::from_u128(user_id).to_string(),
        Utc::now() + Duration::seconds(seconds_till_expiration as i64),
    ))
}

pub async fn sbt_exists<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    wallet_addr: ethabi::Address,
) -> contract::Result<bool> {
    contract
        .query::<bool, _, _, _>(
            "sbtExists",
            wallet_addr,
            wallet_addr,
            contract::Options::default(),
            None,
        )
        .await
}

pub async fn sbt_verify<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    wallet_addr: ethabi::Address,
) -> contract::Result<DateTime<Utc>> {
    let issued_at = contract
        .query::<i64, _, _, _>(
            "sbtVerify",
            wallet_addr,
            wallet_addr,
            contract::Options::default(),
            None,
        )
        .await?;

    DateTime::<Utc>::from_timestamp(issued_at, 0)
        .ok_or_else(|| contract::Error::InvalidOutputType("Not a valid timestamp".to_owned()))
}

#[allow(clippy::too_many_arguments)]
pub async fn mint_sno_sbt<'a, T: web3::Transport>(
    web3_client: &'a web3::Web3<T>,
    req_signer: &'a signer::SBTRequestSigner,
    wallet: &'a SecretKeyRef<'a>,
    wallet_secret: &'a SecretKey,
    sno_wallet: &'a SecretKeyRef<'a>,
    sbt_contract: &'a Contract<T>,
    sno_contract: &'a Contract<T>,
    issuer_contract: &'a Contract<T>,
) -> anyhow::Result<()> {
    let req = req_signer.build_signed_sno_sbt_request(
        wallet.address(),
        sno_wallet.address(),
        sno_contract.address(),
        get_latest_block_timestamp(web3_client.eth()).await?,
    )?;

    let signed_data = hex::decode(&req.data)?;
    let sig_r: [u8; 32] = hex::decode(&req.r)?.try_into().map_err(|e| {
        anyhow::Error::msg(format!(
            "Signature R data is not 32 bytes length. Error: {e:?}"
        ))
    })?;
    let sig_s: [u8; 32] = hex::decode(&req.s)?.try_into().map_err(|e| {
        anyhow::Error::msg(format!(
            "Signature S data is not 32 bytes length. Error: {e:?}"
        ))
    })?;

    // Try to mint SNO SBT
    signed_call(
        issuer_contract,
        "sbtMint",
        (
            sbt_contract.address(),
            signed_data.clone(),
            req.v,
            sig_r,
            sig_s,
        ),
        None,
        wallet_secret,
    )
    .await?;

    Ok(())
}
