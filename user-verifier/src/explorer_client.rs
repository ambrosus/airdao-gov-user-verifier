use chrono::{DateTime, Utc};
use ethabi::{Address, Hash};
use reqwest::Client;
use serde::Deserialize;
use shared::utils;
use std::time::Duration;

pub const PAGE_LIMIT: u64 = 1000;

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
    pub from: Address,
    pub to: Address,
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
        let url = format!("{}{}/all", self.config.url.as_str(), wallet);
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
