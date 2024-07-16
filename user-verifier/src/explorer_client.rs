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
    use assert_matches::assert_matches;
    use chrono::Utc;
    use ethereum_types::Address;

    use super::{ExplorerClient, ExplorerConfig};

    #[tokio::test]
    async fn test_find_first_transaction_before() {
        let client = ExplorerClient::new(ExplorerConfig {
            url: "https://explorer-v2-api.ambrosus.io/v2/addresses/".to_owned(),
            timeout: std::time::Duration::from_secs(10),
        })
        .unwrap();

        let wallet = Address::from(
            <[u8; 20]>::try_from(hex::decode("aeE13A8db3e216A364255EFEbA171ce329100876").unwrap())
                .unwrap(),
        );
        let tx = client
            .find_first_transaction_before(wallet, Utc::now())
            .await;
        assert_matches!(tx, Ok(Some(_)));
    }
}
