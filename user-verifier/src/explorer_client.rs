use anyhow::anyhow;
use chrono::{DateTime, Utc};
use ethabi::{Address, Hash};
use hex::ToHex;
use reqwest::Client;
use serde::Deserialize;
use shared::utils;
use std::time::Duration;

pub const PAGE_LIMIT: u64 = 100;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerConfig {
    pub url: String,
    #[serde(deserialize_with = "utils::de_secs_duration")]
    pub timeout: Duration,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: Hash,
    #[serde(deserialize_with = "utils::de_secs_timestamp_i64")]
    pub timestamp: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    pub total_count: u64,
    pub page_count: u64,
    pub per_page: u64,
    pub has_next: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResponsePaged<T> {
    pub data: T,
    pub pagination: Pagination,
}

#[derive(Clone)]
pub struct ExplorerClient {
    pub config: ExplorerConfig,
    pub inner: Client,
}

impl ExplorerClient {
    pub fn new(config: ExplorerConfig) -> Result<Self, reqwest::Error> {
        Ok(Self {
            inner: Client::builder().timeout(config.timeout).build()?,
            config,
        })
    }

    pub async fn is_healthy(&self) -> anyhow::Result<bool> {
        let url = [self.config.url.as_str(), "/healthz"].concat();

        match self.inner.get(&url).send().await?.text().await.as_deref() {
            Ok("OK") => Ok(true),
            Ok(res) => Err(anyhow!("Unexpected health response: {res}")),
            Err(e) => Err(anyhow!("Error: {e:?}")),
        }
    }

    pub async fn find_first_transaction_before(
        &self,
        wallet: Address,
        before: DateTime<Utc>,
    ) -> Result<Option<Hash>, reqwest::Error> {
        let url = format!(
            "{}{}/all",
            self.config.url.as_str(),
            wallet.encode_hex::<String>()
        );

        tracing::debug!(%url, %wallet, "Request transactions for wallet");

        let mut page = 1u64;

        loop {
            let response: ResponsePaged<Vec<Transaction>> = self
                .inner
                .get(&url)
                .query(&serde_json::json!({
                    "page": page,
                    "limit": PAGE_LIMIT,
                }))
                .send()
                .await?
                .json()
                .await?;

            match response.data.last() {
                Some(transaction) if transaction.timestamp < before => {
                    return Ok(Some(transaction.hash))
                }
                Some(_) if page < response.pagination.page_count => {
                    page = response.pagination.page_count;
                }
                Some(_) | None => break,
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_response() {
        let response = r#"{
            "data": [{
                "blockHash": "0x5256c76ad7a3809eaff33cacabf4d2747bb4a60e73cee32f50407f950f7af782",
                "blockNumber": 31632033,
                "from": "",
                "to": "0xaeE13A8db3e216A364255EFEbA171ce329100876",
                "gasCost": {
                    "wei": "0",
                    "ether": 0
                },
                "gasPrice": "0",
                "gasSent": 0,
                "gasUsed": 0,
                "hash": "0x0f71f742aafc559fc6618a0ed3d2a640fab851f786bfe2143463a6f5571e798a",
                "input": "-",
                "logs": [],
                "nonce": 0,
                "status": "SUCCESS",
                "timestamp": 1721135640,
                "transactionIndex": -1,
                "type": "TokenTransfer",
                "parent": null,
                "hasInners": false,
                "value": {
                    "wei": "8339991955835962979526",
                    "ether": 8339.99195583596,
                    "symbol": ""
                },
                "token": {
                    "address": "0x8d4439F8AC1e5CCF37F9ACb527E59720E0ccA3E3",
                    "name": "",
                    "symbol": "",
                    "decimals": 18,
                    "totalSupply": 0
                }
            }],
            "pagination": {
                "totalCount": 2,
                "pageCount": 2,
                "perPage": 1,
                "next": 2,
                "hasNext": true,
                "current": 1,
                "previous": 1,
                "hasPrevious": false
            }
        }"#;

        serde_json::from_str::<ResponsePaged<Vec<Transaction>>>(response).unwrap();
    }
}
