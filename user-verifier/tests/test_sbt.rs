#![cfg(feature = "enable-integration-tests")]
use assert_matches::assert_matches;
use chrono::{DateTime, Duration, Utc};
use ethereum_types::U256;
use jsonrpc_core::Error as RPCError;
use serde::Serialize;
use std::str::FromStr;
use uuid::Uuid;
use web3::{
    api::Eth,
    contract::{self, Contract, Error::Api as ApiError},
    signing::{Key, SecretKey, SecretKeyRef},
    types::{TransactionReceipt, TransactionRequest},
};

use airdao_gov_user_verifier::signer;

const ERR_SBT_EXPIRED_OR_NOT_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'SBT expired or not exist'";
const ERR_SBT_ALREADY_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'This kind of SBT already exist'";

#[tokio::test]
async fn test_roles() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    // Account #1 private key from Hardhat local node
    let signer_private_key =
        hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")?;
    let signer_secret = web3::signing::SecretKey::from_slice(&signer_private_key)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let issuer_contract = load_contract(
        web3_client.eth(),
        "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
        include_str!("./artifacts/HumanSBTIssuer.json"),
    )?;

    revoke_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert!(!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?));
    grant_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = load_contract(
        web3_client.eth(),
        "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        include_str!("./artifacts/HumanSBT.json"),
    )?;

    revoke_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
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

    // Account #1 private key from Hardhat local node
    let signer_private_key =
        hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")?;
    let signer_secret = web3::signing::SecretKey::from_slice(&signer_private_key)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);
    let signing_key = k256::SecretKey::from_slice(&signer_private_key)?;

    // Account #19 private key from Hardhat local node
    let wallet_secret = web3::signing::SecretKey::from_str(
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    )?;
    let wallet = web3::signing::SecretKeyRef::from(&wallet_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let issuer_contract = load_contract(
        web3_client.eth(),
        "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
        include_str!("./artifacts/HumanSBTIssuer.json"),
    )?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = load_contract(
        web3_client.eth(),
        "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        include_str!("./artifacts/HumanSBT.json"),
    )?;
    assert!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?);

    let signer_config = signer::SignerConfig {
        signing_key: signing_key.into(),
        request_lifetime: std::time::Duration::from_secs(60),
        sbt_lifetime: std::time::Duration::from_secs(3153600000),
        og_eligible_before: Utc::now(),
    };

    let req_signer = signer::SbtRequestSigner::new(signer_config);
    let user_id = uuid::Uuid::from_str("01020304-0506-1122-8877-665544332211")?.as_u128();
    let req = req_signer.build_signed_sbt_request(wallet.address(), user_id, Utc::now())?;

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
        &wallet_secret,
    )
    .await
    .unwrap();
    // Verify that Human SBT can't be minted twice
    let err_already_exist = signed_call(
        &issuer_contract,
        "sbtMint",
        (sbt_contract.address(), signed_data, req.v, sig_r, sig_s),
        &wallet_secret,
    )
    .await
    .unwrap_err();
    assert_matches!(err_already_exist, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_ALREADY_EXIST);

    // Verify that Human SBT is minted correctly
    let (user_id, _) = sbt_verify(&sbt_contract, wallet.address()).await?;
    assert_eq!(user_id.as_str(), "01020304-0506-1122-8877-665544332211");

    // Try to burn Human SBT
    signed_call(
        &issuer_contract,
        "sbtBurn",
        (sbt_contract.address(), wallet.address()),
        &owner_secret,
    )
    .await
    .unwrap();

    // Verify that Human SBT doesn't exist anymore
    let err_no_sbt = sbt_verify(&sbt_contract, wallet.address())
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

    // Account #1 private key from Hardhat local node
    let signer_private_key =
        hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")?;
    let signer_secret = web3::signing::SecretKey::from_slice(&signer_private_key)?;
    let signer = web3::signing::SecretKeyRef::from(&signer_secret);
    let signing_key = k256::SecretKey::from_slice(&signer_private_key)?;

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

    let issuer_contract = load_contract(
        web3_client.eth(),
        "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
        include_str!("./artifacts/OGSBTIssuer.json"),
    )?;
    assert!(has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?);

    let sbt_contract = load_contract(
        web3_client.eth(),
        "0x0165878A594ca255338adfa4d48449f69242Eb8F",
        include_str!("./artifacts/OGSBT.json"),
    )?;
    assert!(has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?);

    let signer_config = signer::SignerConfig {
        signing_key: signing_key.into(),
        request_lifetime: std::time::Duration::from_secs(60),
        sbt_lifetime: std::time::Duration::from_secs(3153600000),
        og_eligible_before: Utc::now(),
    };

    let req_signer = signer::SbtRequestSigner::new(signer_config);
    let req = req_signer.build_signed_og_sbt_request(
        wallet.address(),
        wallet.address(),
        tx_hash,
        Utc::now(),
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
        &wallet_secret,
    )
    .await
    .unwrap();
    // Verify that OG SBT can't be minted twice
    let err_already_exist = signed_call(
        &issuer_contract,
        "sbtMint",
        (sbt_contract.address(), signed_data, req.v, sig_r, sig_s),
        &wallet_secret,
    )
    .await
    .unwrap_err();
    assert_matches!(err_already_exist, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_ALREADY_EXIST);

    // Verify that OG SBT is minted correctly
    let issued_at = og_sbt_verify(&sbt_contract, wallet.address()).await?;
    assert_ne!(issued_at, DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    // Try to burn OG SBT
    signed_call(
        &issuer_contract,
        "sbtBurn",
        (sbt_contract.address(), wallet.address()),
        &owner_secret,
    )
    .await
    .unwrap();

    // Verify that OG SBT doesn't exist anymore
    let zero_date = og_sbt_verify(&sbt_contract, wallet.address()).await?;
    assert_eq!(zero_date, DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    Ok(())
}

pub fn to_bytes<T: Serialize>(structure: T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &structure).map(|_| bytes)
}

pub fn load_contract<T: web3::Transport>(
    eth: Eth<T>,
    address: &str,
    artifact_text: &str,
) -> anyhow::Result<Contract<T>> {
    let sbt_address = ethereum_types::Address::from_str(address)?;
    let artifact = serde_json::from_str::<serde_json::Value>(artifact_text)?;
    let abi = artifact
        .as_object()
        .and_then(|map| map.get("abi").cloned())
        .ok_or_else(|| anyhow::Error::msg("Not a valid contract artifact"))?;

    serde_json::from_value::<ethabi::Contract>(abi)
        .map(|abi| Contract::new(eth, sbt_address, abi))
        .map_err(anyhow::Error::from)
}

pub async fn signed_call<T: web3::Transport, P: contract::tokens::Tokenize + Clone>(
    contract: &Contract<T>,
    method: &str,
    params: P,
    caller_secret: &SecretKey,
) -> contract::Result<TransactionReceipt> {
    let caller = SecretKeyRef::from(caller_secret);

    let estimated_gas = contract
        .estimate_gas(
            method,
            params.clone(),
            caller.address(),
            contract::Options::default(),
        )
        .await?;

    contract
        .signed_call_with_confirmations(
            method,
            params,
            contract::Options {
                gas: estimated_gas.checked_mul(2.into()),
                ..Default::default()
            },
            0,
            caller_secret,
        )
        .await
        .map_err(contract::Error::Api)
}

pub async fn get_role_id<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    role_name: &str,
) -> contract::Result<[u8; 32]> {
    contract
        .query::<[u8; 32], _, _, _>(
            role_name,
            (),
            contract.address(),
            contract::Options::default(),
            None,
        )
        .await
        .map_err(contract::Error::from)
}

pub async fn has_role<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    role_name: &str,
    wallet_addr: ethabi::Address,
) -> anyhow::Result<bool> {
    let role_id = get_role_id(contract, role_name).await?;

    contract
        .query::<bool, _, _, _>(
            "hasRole",
            (role_id, wallet_addr),
            wallet_addr,
            contract::Options::default(),
            None,
        )
        .await
        .map_err(anyhow::Error::from)
}

pub async fn grant_role<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    role_name: &str,
    wallet_addr: ethabi::Address,
    caller: &web3::signing::SecretKey,
) -> contract::Result<TransactionReceipt> {
    let role_id = get_role_id(contract, role_name).await?;

    signed_call(contract, "grantRole", (role_id, wallet_addr), caller).await
}

pub async fn revoke_role<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    role_name: &str,
    wallet_addr: ethabi::Address,
    caller: &web3::signing::SecretKey,
) -> anyhow::Result<TransactionReceipt> {
    let role_id = get_role_id(contract, role_name).await?;

    signed_call(contract, "revokeRole", (role_id, wallet_addr), caller)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn sbt_verify<T: web3::Transport>(
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

pub async fn og_sbt_verify<T: web3::Transport>(
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
