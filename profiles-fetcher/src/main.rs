use chrono::{DateTime, Utc};
use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use shared::{logger, utils};
use std::{fs::File, io::prelude::*};
use tracing::{info, warn};

const REQUEST_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
const REQUEST_LIMIT: usize = 4;
const MAX_PARALLEL_REQUESTS: usize = 5;
const BATCH_SIZE: usize = REQUEST_LIMIT * MAX_PARALLEL_REQUESTS;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
enum SBTReportKind {
    Success(SBTReport),
    Failure(SBTReportError),
    Unavailable,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct SBTReport {
    name: String,
    address: Address,
    issued_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct SBTReportError {
    name: String,
    address: Address,
    error: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct User {
    wallet: Address,
    reports: Vec<SBTReportKind>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct AllUsersReport {
    next: usize,
    users: Vec<User>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let token = std::env::var("TOKEN")?;
    let mut start = 0;
    let mut users = vec![];

    if let Ok(mut file) = File::open("./reports.json") {
        let mut json = String::new();

        file.read_to_string(&mut json)?;

        let all_users = serde_json::from_str::<AllUsersReport>(&json)?;

        start = all_users.next;
        users = all_users.users;
    }

    for batch_start in (start..).step_by(BATCH_SIZE).into_iter() {
        let mut requests = (batch_start..batch_start + BATCH_SIZE)
            .step_by(REQUEST_LIMIT)
            .into_iter()
            .collect::<Vec<_>>();

        info!(start = ?batch_start, limit = ?REQUEST_LIMIT, "Waiting for a batch");

        let mut end = false;
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .timeout(REQUEST_TIMEOUT)
            .build()?;

        let mut fetched_users_count = 0;

        loop {
            if requests.is_empty() {
                break;
            }

            let prepared = requests.iter().map(|start| {
                let client = client.clone();
                let token = token.as_str();

                tokio::time::timeout(REQUEST_TIMEOUT, async move {
                    client
                        .post("https://gov-portal-verifier-api.ambrosus.io/db/sbt-report")
                        .json(&serde_json::json!({
                            "token": token,
                            "start": start,
                            "limit": REQUEST_LIMIT,
                        }))
                        .send()
                        .await
                })
            });

            let results = futures_util::future::join_all(prepared)
                .await
                .into_iter()
                .zip(requests);

            info!(count = ?results.len(), "Fetched results");

            requests = vec![];

            for (result, start) in results {
                match result {
                    Err(_) => {
                        warn!(?start, "Fetch a batch timed out");
                        requests.push(start);
                    }
                    Ok(Err(error)) => {
                        warn!(?start, ?error, "Failed to fetch a batch");
                        requests.push(start);
                    }
                    Ok(Ok(response)) => {
                        let (text, parsed_users) = match response.text().await {
                            Err(error) => {
                                warn!(?start, ?error, "Failed to get response for a batch");
                                requests.push(start);
                                continue;
                            }
                            Ok(text) => {
                                let parsed = serde_json::from_str::<Vec<User>>(&text);
                                (text, parsed)
                            }
                        };

                        let Ok(fetched_users) = parsed_users else {
                            warn!(?text, "Failed to parse users response");
                            requests.push(start);
                            continue;
                        };

                        info!(count = ?fetched_users.len(), "Fetched users");

                        fetched_users_count += fetched_users.len();

                        if fetched_users.is_empty() {
                            end = true;
                            continue;
                        }

                        users.extend(fetched_users.into_iter().filter_map(|user| {
                            let reports = user
                                .reports
                                .into_iter()
                                .filter_map(|report| {
                                    if let SBTReportKind::Unavailable = report {
                                        None
                                    } else {
                                        Some(report)
                                    }
                                })
                                .collect::<Vec<SBTReportKind>>();

                            if reports.is_empty() {
                                None
                            } else {
                                Some(User {
                                    wallet: user.wallet,
                                    reports,
                                })
                            }
                        }));
                    }
                }
            }

            if !requests.is_empty() {
                info!(count = ?requests.len(), "Retry requests...");
            }
        }

        info!(count = ?users.len(), "Total fetched profiles");

        match File::create("./reports.json.tmp") {
            Ok(mut file) => {
                if let Err(error) = file.write_all(
                    serde_json::to_string_pretty(&AllUsersReport {
                        next: batch_start + fetched_users_count,
                        users: users.clone(),
                    })?
                    .as_bytes(),
                ) {
                    warn!(?error, "Failed to write file");
                }
            }
            Err(error) => {
                warn!(?error, "Failed to open file");
            }
        }

        if let Err(error) = std::fs::rename("./reports.json.tmp", "./reports.json") {
            warn!(?error, "Failed to replace file");
        }

        if end {
            break;
        }
    }

    Ok(())
}
