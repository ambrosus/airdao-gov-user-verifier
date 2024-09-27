#![cfg(any(test, feature = "enable-integration-tests"))]
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use ethereum_types::{Address, U256};
use hex::ToHex;
use serde::Serialize;
use web3::{
    api::Eth,
    contract::{self, tokens::Tokenize, Contract},
    signing::{Key, SecretKey, SecretKeyRef},
    types::TransactionReceipt,
};

pub async fn get_latest_block_timestamp<T: web3::Transport>(
    eth: Eth<T>,
) -> anyhow::Result<DateTime<Utc>> {
    let block_id = eth.block_number().await?;
    eth.block(block_id.into())
        .await?
        .and_then(|block| DateTime::<Utc>::from_timestamp(block.timestamp.as_u64() as i64, 0))
        .ok_or_else(|| anyhow!("Block not found"))
}

pub fn to_bytes<T: Serialize>(structure: T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &structure).map(|_| bytes)
}

pub fn load_contract<T: web3::Transport, A>(
    eth: Eth<T>,
    address: A,
    artifact_text: &str,
) -> anyhow::Result<Contract<T>>
where
    A: TryInto<ethereum_types::Address>,
    <A as TryInto<ethereum_types::Address>>::Error:
        serde::ser::StdError + std::marker::Send + std::marker::Sync + 'static,
{
    let contract_address = address.try_into()?;
    let artifact = serde_json::from_str::<serde_json::Value>(artifact_text)?;
    let abi = artifact
        .as_object()
        .and_then(|map| map.get("abi").cloned())
        .ok_or_else(|| anyhow::Error::msg("Not a valid contract artifact"))?;

    serde_json::from_value::<ethabi::Contract>(abi)
        .map(|abi| Contract::new(eth, contract_address, abi))
        .map_err(anyhow::Error::from)
}

pub async fn deploy_upgradeable_contract<T: web3::Transport, P: Tokenize>(
    eth: Eth<T>,
    artifact_text: &str,
    params: P,
    caller_secret: &SecretKey,
) -> anyhow::Result<Contract<T>> {
    let caller = SecretKeyRef::from(caller_secret);

    // Deploy implementation contract
    let impl_contract = deploy_contract(eth.clone(), artifact_text, (), caller_secret).await?;

    let proxy_admin_contract = deploy_contract(
        eth.clone(),
        include_str!("../../../artifacts/ProxyAdmin.json"),
        caller.address(),
        caller_secret,
    )
    .await?;

    let calldata = impl_contract
        .abi()
        .function("initialize")
        .and_then(|function| function.encode_input(&params.into_tokens()))?;

    let proxy_contract = deploy_contract(
        eth.clone(),
        include_str!("../../../artifacts/TransparentUpgradeableProxy.json"),
        (
            impl_contract.address(),
            proxy_admin_contract.address(),
            calldata,
        ),
        caller_secret,
    )
    .await?;

    // Attach ABI to deployed transparent proxy contract
    load_contract(eth, proxy_contract.address(), artifact_text)
}

pub async fn deploy_contract<T: web3::Transport, P: Tokenize>(
    eth: Eth<T>,
    artifact_text: &str,
    params: P,
    caller_secret: &SecretKey,
) -> anyhow::Result<Contract<T>> {
    let caller = SecretKeyRef::from(caller_secret);
    let artifact = serde_json::from_str::<serde_json::Value>(artifact_text)?;
    let abi = artifact
        .as_object()
        .and_then(|map| map.get("abi").cloned())
        .ok_or_else(|| anyhow::Error::msg("Not a valid contract artifact"))?
        .to_string();
    let bytecode = artifact
        .as_object()
        .and_then(|map| map.get("bytecode").cloned())
        .ok_or_else(|| anyhow::Error::msg("Not a valid contract artifact"))?;

    Contract::deploy(eth, abi.as_bytes())?
        .confirmations(0)
        // .options(Options {
        //     ..Default::default()
        // })
        .execute(bytecode.to_string(), params, caller.address())
        .await
        .map_err(anyhow::Error::from)
}

pub async fn signed_call<T: web3::Transport, P: contract::tokens::Tokenize + Clone>(
    contract: &Contract<T>,
    method: &str,
    params: P,
    value: Option<U256>,
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
                value,
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

    signed_call(contract, "grantRole", (role_id, wallet_addr), None, caller).await
}

pub async fn revoke_role<T: web3::Transport>(
    contract: &web3::contract::Contract<T>,
    role_name: &str,
    wallet_addr: ethabi::Address,
    caller: &web3::signing::SecretKey,
) -> anyhow::Result<TransactionReceipt> {
    let role_id = get_role_id(contract, role_name).await?;

    signed_call(contract, "revokeRole", (role_id, wallet_addr), None, caller)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn hardhat_set_coinbase<T: web3::Transport>(
    http: &T,
    address: Address,
) -> anyhow::Result<serde_json::Value> {
    let (set_coinbase_req_id, set_coinbase_call) = http.prepare(
        "hardhat_setCoinbase",
        vec![format!("0x{}", address.encode_hex::<String>()).into()],
    );

    http.send(set_coinbase_req_id, set_coinbase_call)
        .await
        .map_err(anyhow::Error::from)
}

pub fn transaction_cost(receipt: &TransactionReceipt) -> Option<U256> {
    receipt
        .effective_gas_price
        .and_then(|gas_price| gas_price.checked_mul(receipt.cumulative_gas_used))
}
