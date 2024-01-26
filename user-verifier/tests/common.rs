#![cfg(feature = "enable-integration-tests")]
use ethereum_types::H256;
use serde::Serialize;
use std::str::FromStr;
use web3::{
    api::Eth,
    contract::{self, Contract},
    signing::{Key, SecretKey, SecretKeyRef},
};

pub fn to_bytes<T: Serialize>(structure: T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &structure).map(|_| bytes)
}

pub fn init_human_sbt_issuer_contract<T: web3::Transport>(
    eth: Eth<T>,
) -> Result<Contract<T>, anyhow::Error> {
    // Default address where Human SBT Issuer proxy is deployed at Hardhat local node
    let sbt_issuer_address =
        ethereum_types::Address::from_str("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707")?;

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

    Contract::from_json(eth, sbt_issuer_address, &abi_bytes).map_err(anyhow::Error::from)
}

pub fn init_sbt_oracle_contract<T: web3::Transport>(
    eth: Eth<T>,
) -> Result<Contract<T>, anyhow::Error> {
    // Default address where SBT Oracle proxy is deployed at Hardhat local node
    let sbt_oracle_address =
        ethereum_types::Address::from_str("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")?;

    let abi_bytes = to_bytes(serde_json::json!([
          {
            "inputs": [
              {
                "internalType": "address",
                "name": "sbtContract",
                "type": "address"
              },
              {
                "internalType": "address",
                "name": "userWallet",
                "type": "address"
              }
            ],
            "name": "sbtVerify",
            "outputs": [
              {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
              },
              {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
              }
            ],
            "stateMutability": "view",
            "type": "function"
          }
    ]))?;

    Contract::from_json(eth, sbt_oracle_address, &abi_bytes).map_err(anyhow::Error::from)
}

pub async fn signed_call<T: web3::Transport, P: contract::tokens::Tokenize + Clone>(
    contract: &Contract<T>,
    method: &str,
    params: P,
    caller_secret: &SecretKey,
) -> contract::Result<H256> {
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
        .signed_call(
            method,
            params,
            contract::Options {
                gas: estimated_gas.checked_mul(2.into()),
                ..Default::default()
            },
            caller_secret,
        )
        .await
        .map_err(|e| contract::Error::Api(e))
}
