use anyhow::anyhow;
use ethabi::RawLog;
use ethereum_types::{Address, U256};
use ethers::{
    abi::Detokenize,
    contract::{ContractError, EthEvent, EthLogDecode, Event},
    providers::Provider,
    types::Filter,
};
use ethers_providers::{Middleware, PubsubClient};
use futures_util::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::mpsc,
    time::{sleep_until, Instant},
};

const ERR_UNHANDLED_EVENT: &str = "Unhandled event";
const HUMAN_SBT_MINT_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("SBTMint(address,uint256,uint256)");
const NON_EXP_SBT_MINT_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("SBTMint(address)");
const SBT_BURN_EVENT_SIGNATURE: ethereum_types::H256 = shared::event_signature!("SBTBurn(address)");
const REWARD_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("Reward(address,address,uint256,uint256,string,string,string,string)");
const CLAIM_REWARD_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("ClaimReward(address,uint256,uint256)");
const REVERT_REWARD_EVENT_SIGNATURE: ethereum_types::H256 =
    shared::event_signature!("RevertReward(uint256,uint256)");

pub struct EventListener<T: PubsubClient> {
    provider: Arc<Provider<T>>,
    block_number: u64,
    sbt_name_by_addr: HashMap<Address, String>,
    contracts: HashMap<String, Address>,
}

#[derive(Clone)]
struct EventLoopContext {
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

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "Reward")]
pub struct RewardEvent {
    #[ethevent(indexed)]
    pub grantor: Address,
    #[ethevent(indexed)]
    pub wallet: Address,
    pub amount: U256,
    pub timestamp: U256,
    #[ethevent(name = "eventName")]
    pub name: String,
    pub region: String,
    pub community: String,
    pub pseudo: String,
}

impl std::fmt::Display for RewardEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "ClaimReward")]
pub struct ClaimRewardEvent {
    #[ethevent(indexed)]
    pub wallet: Address,
    #[ethevent(indexed)]
    pub id: U256,
    pub amount: U256,
}

impl std::fmt::Display for ClaimRewardEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "RevertReward")]
pub struct RevertRewardEvent {
    #[ethevent(indexed)]
    pub id: U256,
    pub total: U256,
}

impl std::fmt::Display for RevertRewardEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug)]
pub enum GovEvent {
    SBTMint(Address),
    SBTBurn(Address),
    Reward(RewardEvent),
    ClaimReward(Address, u64),
    RevertReward(u64),
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
            // SBT events
            Some(topic) if topic.eq(&HUMAN_SBT_MINT_EVENT_SIGNATURE) => {
                if log.topics.len() == 1 {
                    // Backward compatibility for non-indexed `wallet`
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
                    // Backward compatibility for non-indexed `wallet`
                    <SBTBurnEventV0 as EthLogDecode>::decode_log(log)
                        .map(|event| Self::SBTBurn(event.wallet))
                } else {
                    <SBTBurnEvent as EthLogDecode>::decode_log(log)
                        .map(|event| Self::SBTBurn(event.wallet))
                }
            }

            // Reward distribution events
            Some(topic) if topic.eq(&REWARD_EVENT_SIGNATURE) => {
                <RewardEvent as EthLogDecode>::decode_log(log).map(Self::Reward)
            }
            Some(topic) if topic.eq(&CLAIM_REWARD_EVENT_SIGNATURE) => {
                <ClaimRewardEvent as EthLogDecode>::decode_log(log)
                    .map(|event| Self::ClaimReward(event.wallet, event.id.as_u64()))
            }
            Some(topic) if topic.eq(&REVERT_REWARD_EVENT_SIGNATURE) => {
                <RevertRewardEvent as EthLogDecode>::decode_log(log)
                    .map(|event| Self::RevertReward(event.id.as_u64()))
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
        contracts: HashMap<String, Address>,
        provider: Arc<Provider<T>>,
        block_number: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            provider,
            block_number,
            sbt_name_by_addr: contracts.iter().map(|(k, v)| (*v, k.clone())).collect(),
            contracts,
        })
    }

    pub async fn start(
        &self,
        tx: mpsc::UnboundedSender<GovEventNotification>,
    ) -> anyhow::Result<()> {
        let mut context = EventLoopContext {
            tx,
            block: self.block_number,
        };

        let idle_interval = std::time::Duration::from_secs(10);
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
                Filter::new().address(self.contracts.values().copied().collect::<Vec<_>>()),
                self.provider.clone(),
            )
            .from_block(context.block);

            // Reset filter by topics created by [`EthEvent::new`] call above
            event.filter.topics = Default::default();

            let mut blocks_stream = match self.provider.subscribe_blocks().await {
                Ok(stream) => stream,
                Err(e) => {
                    error = Some(EventLoopError::Unrecoverable(anyhow::Error::msg(format!(
                        "Failed to subscribe blocks: {e:?}",
                    ))));
                    continue;
                }
            };

            let mut events_stream = match event.subscribe_with_meta().await {
                Ok(stream) => stream,
                Err(e) => {
                    error = Some(EventLoopError::Unrecoverable(anyhow::Error::msg(format!(
                        "Failed to subscribe government events: {e:?}",
                    ))));
                    continue;
                }
            };

            loop {
                let idle_until = Instant::now() + idle_interval;

                tracing::trace!(block = %context.block, "Wait for next government event...");

                let event = tokio::select! {
                    event = events_stream.next() => {
                        match event {
                            Some(event) => event,
                            None => {
                                error = Some(EventLoopError::Recoverable(anyhow!(
                                    "Subscription to government events ended"
                                )));
                                break;
                            }
                        }
                    }
                    block = blocks_stream.next() => {
                        match block {
                            Some(block) => {
                                tracing::debug!("New block {:?}", block.number);
                                continue;
                            },
                            None => {
                                error = Some(EventLoopError::Recoverable(anyhow!(
                                    "Subscription to blocks ended"
                                )));
                                break;
                            }
                        }
                    }
                    _ = context.tx.closed() => {
                        error = Some(EventLoopError::Unrecoverable(anyhow!(
                            "Event notification channel has been dropped"
                        )));
                        break;
                    }
                    _ = sleep_until(idle_until) => {
                        error = Some(EventLoopError::Recoverable(anyhow!(
                            "No blockchain events within {}s", idle_interval.as_secs(),
                        )));
                        break;
                    }
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
