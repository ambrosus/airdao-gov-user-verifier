use anyhow::anyhow;
use ethabi::RawLog;
use ethereum_types::{Address, U256};
use ethers::{
    abi::Detokenize,
    contract::{ContractError, EthEvent, EthLogDecode, Event},
    providers::Provider,
    types::Filter,
};
use ethers_providers::PubsubClient;
use futures_util::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

use crate::config::AppConfig;

const ERR_UNHANDLED_EVENT: &str = "Unhandled event";
const HUMAN_SBT_MINT_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("SBTMint(address,uint256,uint256)");
const NON_EXP_SBT_MINT_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("SBTMint(address)");
const SBT_BURN_EVENT_SIGNATURE: ethereum_types::H256 = shared::event_signature!("SBTBurn(address)");

pub struct EventListener<T: PubsubClient> {
    provider: Arc<Provider<T>>,
    block_number: u64,
    sbt_name_by_addr: HashMap<Address, String>,
    config: Arc<AppConfig>,
}

#[derive(Clone)]
struct EventLoopContext {
    #[allow(unused)]
    config: Arc<AppConfig>,
    tx: mpsc::UnboundedSender<GovEventNotification>,
    block: u64,
}

#[derive(Debug)]
enum EventLoopError {
    Recoverable(anyhow::Error),
    Unrecoverable(anyhow::Error),
}

/// Deprecated event without indexed wallet address
#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "SBTMint")]
pub struct GovSBTMintEventV0 {
    #[ethevent(name = "userWallet")]
    pub wallet: Address,
    #[ethevent(name = "userId")]
    pub user_id: U256,
    #[ethevent(name = "expiresAt")]
    pub expires_at: U256,
}

impl std::fmt::Display for GovSBTMintEventV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "SBTMint")]
pub struct GovSBTMintEvent {
    #[ethevent(indexed, name = "userWallet")]
    pub wallet: Address,
    #[ethevent(name = "userId")]
    pub user_id: U256,
    #[ethevent(name = "expiresAt")]
    pub expires_at: U256,
}

impl std::fmt::Display for GovSBTMintEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "SBTMint")]
pub struct NonExpSBTMintEvent {
    #[ethevent(indexed, name = "userWallet")]
    pub wallet: Address,
}

impl std::fmt::Display for NonExpSBTMintEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Deprecated event without indexed wallet address
#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "SBTBurn")]
pub struct SBTBurnEventV0 {
    #[ethevent(name = "userWallet")]
    pub wallet: Address,
}

impl std::fmt::Display for SBTBurnEventV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug)]
pub struct GovEventNotification {
    pub event: GovEvent,
    pub contract_address: Address,
    pub contract_name: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "SBTBurn")]
pub struct SBTBurnEvent {
    #[ethevent(indexed, name = "userWallet")]
    pub wallet: Address,
}

impl std::fmt::Display for SBTBurnEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug)]
pub enum GovEvent {
    SBTMint(Address),
    SBTBurn(Address),
}

/// Required trait for [`EthEvent::new`]
impl Detokenize for GovEvent {
    fn from_tokens(_: Vec<ethabi::Token>) -> Result<Self, ethers::abi::InvalidOutputType>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

/// Required trait for [`EthEvent::new`]
impl EthEvent for GovEvent {
    fn abi_signature() -> std::borrow::Cow<'static, str> {
        Default::default()
    }

    fn decode_log(log: &RawLog) -> Result<Self, ethers::core::abi::Error>
    where
        Self: Sized,
    {
        match log.topics.first() {
            Some(topic) if topic.eq(&HUMAN_SBT_MINT_EVENT_SIGNATURE) => {
                if log.topics.len() == 1 {
                    <GovSBTMintEventV0 as EthLogDecode>::decode_log(log)
                        .map(|event| Self::SBTMint(event.wallet))
                } else {
                    <GovSBTMintEvent as EthLogDecode>::decode_log(log)
                        .map(|event| Self::SBTMint(event.wallet))
                }
            }
            Some(topic) if topic.eq(&NON_EXP_SBT_MINT_EVENT_SIGNATURE) => {
                <NonExpSBTMintEvent as EthLogDecode>::decode_log(log)
                    .map(|event| Self::SBTMint(event.wallet))
            }
            Some(topic) if topic.eq(&SBT_BURN_EVENT_SIGNATURE) => {
                if log.topics.len() == 1 {
                    <SBTBurnEventV0 as EthLogDecode>::decode_log(log)
                        .map(|event| Self::SBTBurn(event.wallet))
                } else {
                    <SBTBurnEvent as EthLogDecode>::decode_log(log)
                        .map(|event| Self::SBTBurn(event.wallet))
                }
            }
            Some(_) | None => Err(ethabi::Error::Other(ERR_UNHANDLED_EVENT.into())),
        }
    }

    fn is_anonymous() -> bool {
        unreachable!()
    }

    fn name() -> std::borrow::Cow<'static, str> {
        unreachable!()
    }

    fn signature() -> ethereum_types::H256 {
        unreachable!()
    }
}

impl<T: PubsubClient> EventListener<T> {
    pub fn new(
        config: AppConfig,
        provider: Arc<Provider<T>>,
        block_number: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            provider,
            block_number,
            sbt_name_by_addr: config
                .contracts
                .iter()
                .map(|(k, v)| (*v, k.clone()))
                .collect(),
            config: Arc::new(config),
        })
    }

    pub async fn start(
        &self,
        tx: mpsc::UnboundedSender<GovEventNotification>,
    ) -> anyhow::Result<()> {
        let mut context = EventLoopContext {
            config: self.config.clone(),
            tx,
            block: self.block_number,
        };

        let mut error = None;

        loop {
            match error.as_ref() {
                Some(EventLoopError::Recoverable(e)) => {
                    tracing::warn!("Recoverable event loop error {e:?}. Restarting...");
                }
                Some(EventLoopError::Unrecoverable(e)) => {
                    tracing::warn!("Unrecoverable event loop error {e:?}. Stopping...");
                    break;
                }
                None => (),
            };

            let mut event: Event<Arc<Provider<T>>, Provider<T>, _> = EthEvent::new(
                Filter::new().address(self.config.contracts.values().copied().collect::<Vec<_>>()),
                self.provider.clone(),
            )
            .from_block(context.block);

            // Reset filter by topics created by [`EthEvent::new`] call above
            event.filter.topics = Default::default();

            let stream_res = event.subscribe_with_meta().await;

            let Ok(mut stream) = stream_res else {
                error = Some(EventLoopError::Recoverable(anyhow::Error::msg(format!(
                    "Failed to subscribe government events: {:?}",
                    stream_res.err()
                ))));
                continue;
            };

            loop {
                tracing::trace!(block = %context.block, "Wait for next government event...");

                let Some(event) = stream.next().await else {
                    error = Some(EventLoopError::Recoverable(anyhow!(
                        "Subscription to SBT events ended."
                    )));
                    break;
                };

                match event {
                    Ok((event, meta)) => {
                        let block_number = meta.block_number.as_u64();
                        let notification = GovEventNotification {
                            event,
                            contract_name: self
                                .sbt_name_by_addr
                                .get(&meta.address)
                                .cloned()
                                .unwrap_or_default(),
                            contract_address: meta.address,
                            block_number,
                        };

                        if let Err(e) = context.tx.send(notification) {
                            error = Some(EventLoopError::Unrecoverable(anyhow!(
                                "Failed to send government event notification: {e:?}"
                            )));
                            break;
                        } else {
                            context.block = block_number;
                        }
                    }
                    Err(ContractError::DecodingError(ethabi::Error::Other(
                        std::borrow::Cow::Borrowed(ERR_UNHANDLED_EVENT),
                    ))) => {
                        continue;
                    }
                    Err(e) => {
                        error = Some(EventLoopError::Recoverable(anyhow!(
                            "Failed to receive government event: {e:?}"
                        )));
                        break;
                    }
                }
            }

            // TODO: make sleep configurable
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }

        Ok(())
    }
}

// impl<
//         B: Clone + std::borrow::Borrow<M> + Send + Sync + 'static,
//         M: Middleware + std::fmt::Debug + Clone + 'static,
//     > EventLoopContext<B, M>
// {
//     async fn update_application(&mut self, wallet: Address) -> anyhow::Result<TransactionReceipt> {
//         self
//             .voting_contract
//             .method::<_, ()>("registerByWallet", wallet)?
//             .send()
//             .await?
//             .confirmations(1)
//             .await?
//             .ok_or_else(|| {
//                 anyhow::Error::msg(format!("Failed to update application state for user (wallet: {wallet:?}). No transaction receipt."))
//             })
//     }
// }
