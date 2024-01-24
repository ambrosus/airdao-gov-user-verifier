mod common;

use chrono::Utc;
use std::str::FromStr;
use web3::{
    contract::{self, Contract},
    signing::Key,
};

use airdao_gov_user_verifier::signer;

use common::to_bytes;

#[tokio::test]
async fn test_sbt_mint() -> Result<(), anyhow::Error> {
    // Account #19 private key from Hardhat local node
    let wallet_secret = web3::signing::SecretKey::from_str(
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    )?;
    let wallet = web3::signing::SecretKeyRef::from(&wallet_secret);

    // Default address where Human SBT Issuer proxy is deployed at Hardhat local node
    let sbt_issuer_address =
        ethereum_types::Address::from_str("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707")?;

    // Default http url for Hardhat local node
    let http = web3::transports::Http::new("http://127.0.0.1:8545")?;
    let web3_client = web3::Web3::new(http);

    let abi_bytes = to_bytes(serde_json::json!([
          {
            "inputs": [
              {
                "internalType": "address",
                "name": "userWallet",
                "type": "address"
              }
            ],
            "name": "sbtBurn",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
          },
          {
            "inputs": [
              {
                "internalType": "bytes",
                "name": "signedData",
                "type": "bytes"
              },
              {
                "internalType": "uint8",
                "name": "v",
                "type": "uint8"
              },
              {
                "internalType": "bytes32",
                "name": "r",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "s",
                "type": "bytes32"
              }
            ],
            "name": "sbtMint",
            "outputs": [],
            "stateMutability": "payable",
            "type": "function"
          }
    ]))?;

    let contract = Contract::from_json(web3_client.eth(), sbt_issuer_address, &abi_bytes)?;

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

    let estimated_gas = contract
        .estimate_gas(
            "sbtMint",
            (signed_data.clone(), req.v, sig_r, sig_s),
            wallet.address(),
            contract::Options::default(),
        )
        .await?;

    contract
        .signed_call(
            "sbtMint",
            (signed_data, req.v, sig_r, sig_s),
            contract::Options {
                gas: Some(
                    estimated_gas
                        .checked_mul(2.into())
                        .ok_or(anyhow::Error::msg("Gas computation failure"))?,
                ),
                ..Default::default()
            },
            &wallet_secret,
        )
        .await
        .unwrap();

    // TODO: verify token was minted
    Ok(())
}

// TODO: add sbtBurn test
