use ethereum_types::Address;
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub redis: String,
    pub rpc_node: String,
    pub voting: VotingConfig,
    #[serde(deserialize_with = "shared::utils::de_secp256k1_signing_key")]
    pub moderator_key: SigningKey,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VotingConfig {
    pub artifact: String,
    pub contract: Address,
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub registration_duration: Duration,
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub discussion_duration: Duration,
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub voting_duration: Duration,
}
