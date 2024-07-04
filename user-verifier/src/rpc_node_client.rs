use serde::Deserialize;
use shared::utils;
use web3::{contract, transports::http::Http, Web3};

#[derive(Clone)]
pub struct RpcNodeClient {
    inner: Web3<Http>,
    pub config: RpcNodeConfig,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RpcNodeConfig {
    url: String,
    #[serde(deserialize_with = "utils::de_secs_duration")]
    pub request_timeout: std::time::Duration,
}

impl RpcNodeClient {
    pub fn new(config: RpcNodeConfig) -> Result<Self, web3::error::Error> {
        Ok(Self {
            inner: Web3::new(Http::new(&config.url)?),
            config,
        })
    }

    pub fn load_contract(
        &self,
        address: ethereum_types::Address,
        artifact_text: &str,
    ) -> contract::Result<contract::Contract<Http>> {
        let abi = serde_json::from_str::<serde_json::Value>(artifact_text)
            .map_err(|e| {
                contract::Error::Abi(ethabi::Error::Other(
                    format!("Not a valid artifact JSON: {e}").into(),
                ))
            })
            .and_then(|artifact| {
                artifact
                    .as_object()
                    .and_then(|map| map.get("abi").cloned())
                    .ok_or_else(|| {
                        contract::Error::Abi(ethabi::Error::Other(
                            "Failed to find ABI in artifact".into(),
                        ))
                    })
            })?;

        serde_json::from_value::<ethabi::Contract>(abi)
            .map(|abi| contract::Contract::new(self.inner.eth(), address, abi))
            .map_err(|e| {
                contract::Error::Abi(ethabi::Error::Other(
                    format!("Failed to load contract from ABI: {e}").into(),
                ))
            })
    }
}
