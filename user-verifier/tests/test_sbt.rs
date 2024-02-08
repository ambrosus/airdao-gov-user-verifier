#![cfg(feature = "enable-integration-tests")]
mod common;

use assert_matches::assert_matches;
use chrono::Utc;
use jsonrpc_core::Error as RPCError;
use std::str::FromStr;
use web3::{contract::Error::Api as ApiError, signing::Key};

use airdao_gov_user_verifier::signer;

use common::{init_human_sbt_contract, init_human_sbt_issuer_contract, signed_call};

use crate::common::{grant_role, has_role, revoke_role, sbt_verify};

const ERR_SBT_EXPIRED_OR_NOT_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'SBT expired or not exist'";
const ERR_SBT_ALREADY_EXIST: &str = "Error: VM Exception while processing transaction: reverted with reason string 'Non-expired Human SBT already exist'";

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

    let issuer_contract = init_human_sbt_issuer_contract(
        web3_client.eth(),
        "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    )?;

    revoke_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert_eq!(
        false,
        has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?
    );
    grant_role(
        &issuer_contract,
        "SIGN_PROVIDER_ROLE",
        signer.address(),
        &owner_secret,
    )
    .await?;
    assert_eq!(
        true,
        has_role(&issuer_contract, "SIGN_PROVIDER_ROLE", signer.address()).await?
    );

    let sbt_contract = init_human_sbt_contract(
        web3_client.eth(),
        "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    )?;

    revoke_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
    assert_eq!(
        false,
        has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?
    );
    grant_role(
        &sbt_contract,
        "ISSUER_ROLE",
        issuer_contract.address(),
        &owner_secret,
    )
    .await?;
    assert_eq!(
        true,
        has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?
    );

    Ok(())
}

#[tokio::test]
async fn test_sbt() -> Result<(), anyhow::Error> {
    // Account #0 private key from Hardhat local node
    let owner_secret = web3::signing::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )?;

    // Account #1 private key from Hardhat local node
    let signer_private_key =
        hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")?;
    let signer_secret = web3::signing::SecretKey::from_slice(&signer_private_key)?;
    let signing_key = k256::SecretKey::from_slice(&signer_private_key)?;

    // Account #19 private key from Hardhat local node
    let wallet_secret = web3::signing::SecretKey::from_str(
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    )?;
    let wallet = web3::signing::SecretKeyRef::from(&wallet_secret);

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let issuer_contract = init_human_sbt_issuer_contract(
        web3_client.eth(),
        "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    )?;
    assert_eq!(
        true,
        has_role(
            &issuer_contract,
            "SIGN_PROVIDER_ROLE",
            web3::signing::SecretKeyRef::from(&signer_secret).address()
        )
        .await?
    );

    let sbt_contract = init_human_sbt_contract(
        web3_client.eth(),
        "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    )?;
    assert_eq!(
        true,
        has_role(&sbt_contract, "ISSUER_ROLE", issuer_contract.address()).await?
    );

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
