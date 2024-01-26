#![cfg(feature = "enable-integration-tests")]
mod common;

use assert_matches::assert_matches;
use chrono::Utc;
use ethereum_types::Address;
use jsonrpc_core::Error as RPCError;
use std::str::FromStr;
use uuid::Uuid;
use web3::{
    contract::{self, Error::Api as ApiError},
    signing::Key,
};

use airdao_gov_user_verifier::signer;

use common::{init_human_sbt_issuer_contract, init_sbt_oracle_contract, signed_call};

const ERR_SBT_EXPIRED_OR_NOT_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'SBT expired or not exist'";
const ERR_SBT_ALREADY_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'Non-expired Human SBT already exist'";

#[tokio::test]
async fn test_sbt() -> Result<(), anyhow::Error> {
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

    let human_sbt_addr = Address::from_str("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9").unwrap();
    let issuer_contract = init_human_sbt_issuer_contract(web3_client.eth())?;
    let oracle_contract = init_sbt_oracle_contract(web3_client.eth())?;

    // Account #1 private key from Hardhat local node
    let signer_private_key =
        hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")?;
    let signing_key = k256::SecretKey::from_slice(&signer_private_key)?;

    let signer_config = signer::SignerConfig {
        signing_key: signing_key.into(),
        request_lifetime: std::time::Duration::from_secs(60),
        sbt_lifetime: std::time::Duration::from_secs(3153600000),
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
        (signed_data.clone(), req.v, sig_r, sig_s),
        &wallet_secret,
    )
    .await
    .unwrap();
    // Verify that Human SBT can't be minted twice
    let err_already_exist = signed_call(
        &issuer_contract,
        "sbtMint",
        (signed_data, req.v, sig_r, sig_s),
        &wallet_secret,
    )
    .await
    .unwrap_err();
    assert_matches!(err_already_exist, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_ALREADY_EXIST);

    // Verify that Human SBT is minted correctly
    let (user_id, _) = oracle_contract
        .query::<(u128, u64), _, _, _>(
            "sbtVerify",
            (human_sbt_addr, wallet.address()),
            wallet.address(),
            contract::Options::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        Uuid::from_u128(user_id).to_string(),
        "01020304-0506-1122-8877-665544332211"
    );

    // Try to burn Human SBT
    signed_call(&issuer_contract, "sbtBurn", wallet.address(), &owner_secret)
        .await
        .unwrap();

    // Verify that Human SBT doesn't exist anymore
    let err_no_sbt = oracle_contract
        .query::<(u128, u64), _, _, _>(
            "sbtVerify",
            (human_sbt_addr, wallet.address()),
            wallet.address(),
            contract::Options::default(),
            None,
        )
        .await
        .unwrap_err();
    assert_matches!(err_no_sbt, ApiError(web3::Error::Rpc(RPCError { message, .. })) if message.as_str() == ERR_SBT_EXPIRED_OR_NOT_EXIST);

    Ok(())
}
