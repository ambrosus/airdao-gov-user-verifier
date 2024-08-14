use chrono::{DateTime, Utc};
use ethabi::Address;
use ethereum_types::U256;
use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};
use web3::{contract, transports::Http};

use shared::rpc_node_client::RpcNodeClient;

#[allow(clippy::upper_case_acronyms)]
pub trait SBT {
    fn sbt_issued_at(
        &self,
        wallet: Address,
    ) -> impl std::future::Future<Output = contract::Result<Option<DateTime<Utc>>>> + Send;
}

#[derive(Clone)]
pub enum SBTContract {
    HumanSBT(HumanSBT),
    NonExpiringSBT(NonExpiringSBT),
}

impl SBTContract {
    pub fn address(&self) -> Address {
        match self {
            Self::HumanSBT(sbt) => sbt.contract.address(),
            Self::NonExpiringSBT(sbt) => sbt.contract.address(),
        }
    }
}

impl SBT for SBTContract {
    async fn sbt_issued_at(&self, wallet: Address) -> contract::Result<Option<DateTime<Utc>>> {
        match self {
            Self::HumanSBT(sbt) => sbt.sbt_issued_at(wallet).await,
            Self::NonExpiringSBT(sbt) => sbt.sbt_issued_at(wallet).await,
        }
    }
}

#[derive(Clone)]
pub struct NonExpiringSBT {
    pub contract: contract::Contract<Http>,
    request_timeout: std::time::Duration,
}

#[derive(Clone)]
pub struct HumanSBT {
    pub contract: contract::Contract<Http>,
    request_timeout: std::time::Duration,
}

#[derive(Deserialize_enum_str, Serialize_enum_str, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SBTKind {
    HumanSBT,
    #[serde(other)]
    NonExpiring(NonExpiringSBTKind),
}

#[derive(Deserialize_enum_str, Serialize_enum_str, Clone, Debug, PartialEq, Eq, Hash)]
pub enum NonExpiringSBTKind {
    #[serde(rename = "SNOSBT")]
    ServerNodeOperatorSBT,
    #[serde(rename = "OGSBT")]
    OriginalGangsterSBT,
    CouncilSBT,
    ExCouncilSBT,
    TokenHolderSBT,
    AmbassadorSBT,
    ExternalDevSBT,
    InHouseDevSBT,
    GWGMemberSBT,
    InvestorSBT,
    PartnerSBT,
    TeamSBT,
}

impl NonExpiringSBT {
    pub async fn new(contract: Address, client: &RpcNodeClient) -> contract::Result<Self> {
        let non_expiring_sbt_artifact = include_str!("../artifacts/INonExpSBT.json");
        let request_timeout = client.config.request_timeout;
        let non_exp_sbt_contract = client.load_contract(contract, non_expiring_sbt_artifact)?;

        Ok(Self {
            contract: non_exp_sbt_contract,
            request_timeout,
        })
    }
}

impl SBT for NonExpiringSBT {
    async fn sbt_issued_at(&self, wallet: Address) -> contract::Result<Option<DateTime<Utc>>> {
        tokio::time::timeout(
            self.request_timeout,
            self.contract.query(
                "sbtIssuedAt",
                wallet,
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into())))?
        .map(|issued_at: U256| {
            if issued_at.is_zero() {
                None
            } else {
                DateTime::from_timestamp(issued_at.as_u64() as i64, 0)
            }
        })
    }
}

impl HumanSBT {
    pub async fn new(contract: Address, client: &RpcNodeClient) -> contract::Result<Self> {
        let non_expiring_sbt_artifact = include_str!("../artifacts/HumanSBT.json");
        let request_timeout = client.config.request_timeout;
        let non_exp_sbt_contract = client.load_contract(contract, non_expiring_sbt_artifact)?;

        Ok(Self {
            contract: non_exp_sbt_contract,
            request_timeout,
        })
    }
}

impl SBT for HumanSBT {
    async fn sbt_issued_at(&self, wallet: Address) -> contract::Result<Option<DateTime<Utc>>> {
        let exists: bool = tokio::time::timeout(
            self.request_timeout,
            self.contract.query(
                "sbtExists",
                wallet,
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| {
            contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into()))
        })??;

        if !exists {
            return Ok(None);
        }

        tokio::time::timeout(
            self.request_timeout,
            self.contract.query(
                "sbtVerify",
                wallet,
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into())))?
        .map(|(_, expired_in): (U256, U256)| {
            // Current HumanSBT implementation doesn't provide issued date but only how much time left till expiration.
            // It's lifetime limit is configured to 100 years.
            let issued_at = expired_in
                .checked_add(Utc::now().timestamp().into())?
                .checked_sub(3153600000000u64.into())?;
            if issued_at.is_zero() {
                None
            } else {
                DateTime::from_timestamp(issued_at.as_u64() as i64, 0)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SBTKind;

    #[test]
    fn de_sbt_kind() {
        "HumanSBT".parse::<SBTKind>().unwrap();
        "AmbassadorSBT".parse::<SBTKind>().unwrap();
        "SNOSBT".parse::<SBTKind>().unwrap();
    }
}
