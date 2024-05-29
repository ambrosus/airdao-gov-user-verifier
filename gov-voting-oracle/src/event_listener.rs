use chrono::Utc;
use ethereum_types::{Address, U256};
use ethers::{
    contract::{Contract, ContractInstance, EthAbiType, EthEvent, Event},
    core::{abi::Abi, types::transaction::response::TransactionReceipt},
    providers::{Http, Middleware, Provider},
    types::H256,
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::{convert::TryFrom, sync::Arc};
use tokio::sync::mpsc;

use crate::config::{AppConfig, VotingConfig};

pub struct EventListener {
    config: Arc<AppConfig>,
    voting_artifact: Arc<ContractArtifact>,
}

#[derive(Clone)]
struct EventLoopContext<B: std::borrow::Borrow<M>, M> {
    config: Arc<AppConfig>,
    voting_contract: ContractInstance<B, M>,
    tx: mpsc::UnboundedSender<(Address, ApplicationState, H256)>,
    block: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractArtifact {
    abi: Abi,
}

#[derive(Debug)]
enum EventLoopError {
    Recoverable(anyhow::Error),
    Unrecoverable(anyhow::Error),
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "VotingStart")]
pub struct VotingStartEvent {
    #[ethevent(indexed)]
    pub wallet: Address,
    #[ethevent(indexed)]
    pub id: U256,
    pub timestamp: U256,
}

impl std::fmt::Display for VotingStartEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, EthAbiType)]
pub struct ApplicationState {
    pub orig_voting_multiplier: U256,
    pub updated_at: U256,
    pub actual_voting_multiplier: U256,
}

impl std::fmt::Display for ApplicationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ApplicationState {
    fn requires_update(&self) -> bool {
        self.orig_voting_multiplier > self.actual_voting_multiplier
    }
}

#[derive(Debug)]
struct Voting {
    pub owner: Address,
    pub id: u64,
    pub started_at: u64,
}

impl std::fmt::Display for Voting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(id: {}, owner: {}, started_at: {})",
            self.id, self.owner, self.started_at
        )
    }
}

enum VotingState {
    Registration(Voting),
    Discussion(Voting),
    Ongoing(Voting),
    Finished(Voting),
}

impl VotingState {
    fn new(start_event: &VotingStartEvent, config: &VotingConfig) -> Self {
        let now = Utc::now().timestamp() as u64;
        let voting = Voting {
            owner: start_event.wallet,
            id: start_event.id.as_u64(),
            started_at: start_event.timestamp.as_u64(),
        };

        if Self::is_registration_started(start_event, config, now) {
            Self::Registration(voting)
        } else if Self::is_discussion_started(start_event, config, now) {
            Self::Discussion(voting)
        } else if Self::is_voting_finished(start_event, config, now) {
            Self::Finished(voting)
        } else {
            Self::Ongoing(voting)
        }
    }

    fn is_voting_finished(start_event: &VotingStartEvent, config: &VotingConfig, now: u64) -> bool {
        start_event.timestamp.as_u64()
            + config.registration_duration.as_secs()
            + config.discussion_duration.as_secs()
            + config.voting_duration.as_secs()
            < now
    }

    fn is_discussion_started(
        start_event: &VotingStartEvent,
        config: &VotingConfig,
        now: u64,
    ) -> bool {
        start_event.timestamp.as_u64() + config.registration_duration.as_secs() <= now
            && start_event.timestamp.as_u64()
                + config.registration_duration.as_secs()
                + config.discussion_duration.as_secs()
                > now
    }

    fn is_registration_started(
        start_event: &VotingStartEvent,
        config: &VotingConfig,
        now: u64,
    ) -> bool {
        start_event.timestamp.as_u64() <= now
            && start_event.timestamp.as_u64() + config.registration_duration.as_secs() > now
    }
}

#[derive(Debug, Clone, EthEvent)]
#[ethevent(name = "RegisterForVote")]
pub struct RegisterForVoteEvent {
    #[ethevent(indexed)]
    pub wallet: Address,
    pub voting_multiplier: U256,
    #[ethevent(indexed)]
    pub id: U256,
    pub timestamp: U256,
}

impl std::fmt::Display for RegisterForVoteEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl EventListener {
    pub fn new(config: AppConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config: Arc::new(config),
            voting_artifact: Arc::new(serde_json::from_str::<ContractArtifact>(include_str!(
                "../artifacts/VotingContract.json"
            ))?),
        })
    }

    pub fn start(
        &self,
        tx: mpsc::UnboundedSender<(Address, ApplicationState, H256)>,
    ) -> anyhow::Result<()> {
        // TODO: make configurable provider url
        let provider = Arc::new(Provider::<Http>::try_from("http://localhost:8545")?);

        let voting_contract = Contract::new(
            self.config.voting.contract,
            self.voting_artifact.abi.clone(),
            provider,
        );

        let mut context = EventLoopContext {
            config: self.config.clone(),
            voting_contract,
            tx,
            block: 0,
        };

        tokio::spawn(async move {
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

                let event: Event<_, _, _> = context
                    .voting_contract
                    .event::<VotingStartEvent>()
                    .from_block(context.block)
                    .address(context.voting_contract.address().into());
                let stream_res = event.stream().await;
                let Ok(mut stream) = stream_res else {
                    error = Some(EventLoopError::Recoverable(anyhow::Error::msg(format!(
                        "Failed to subscribe `VotingStart` events: {:?}",
                        stream_res.err()
                    ))));
                    continue;
                };

                loop {
                    tracing::info!(block = %context.block, "Wait for VotingStart event...");

                    let Some(event) = stream.next().await else {
                        error = Some(EventLoopError::Recoverable(anyhow::Error::msg(
                            "Subscription to `VotingStart` event ended.".to_string(),
                        )));
                        break;
                    };

                    let voting_state = match &event {
                        Ok(voting_event) => VotingState::new(voting_event, &context.config.voting),
                        Err(e) => {
                            error = Some(EventLoopError::Recoverable(anyhow::Error::msg(format!(
                                "Failed to receive `VotingStart` event: {e:?}"
                            ))));
                            break;
                        }
                    };

                    match voting_state {
                        VotingState::Registration(voting) => {
                            tracing::info!(
                                %voting,
                                "Wait for discussion period to start"
                            );
                            break;
                        }
                        VotingState::Discussion(voting) => {
                            if let Err(e) = context.handle_voting_start_event(&voting).await {
                                tracing::warn!(%voting,
                                    "Failed to handle users applications: {e:?}"
                                );

                                error = Some(e);

                                break;
                            }

                            // All votes has been processed, skip the block
                            context.block = voting.id + 1;
                        }
                        VotingState::Ongoing(voting) => {
                            tracing::info!(
                                %voting,
                                "Skip ongoing voting",
                            );

                            // Discussion period ended, skip the block
                            context.block = voting.id + 1;
                        }
                        VotingState::Finished(voting) => {
                            tracing::info!(%voting, "Skip finished voting");

                            // Voting is finished, skip the block
                            context.block = voting.id + 1;
                        }
                    }
                }

                // TODO: make sleep configurable
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        });

        Ok(())
    }
}

impl<
        B: Clone + std::borrow::Borrow<M> + Send + Sync + 'static,
        M: Middleware + std::fmt::Debug + Clone + 'static,
    > EventLoopContext<B, M>
{
    async fn update_application(&mut self, wallet: Address) -> anyhow::Result<TransactionReceipt> {
        self
            .voting_contract
            .method::<_, ()>("registerByWallet", wallet)?
            .send()
            .await?
            .confirmations(1)
            .await?
            .ok_or_else(|| {
                anyhow::Error::msg(format!("Failed to update application state for user (wallet: {wallet:?}). No transaction receipt."))
            })
    }

    async fn handle_voting_start_event(&mut self, voting: &Voting) -> Result<(), EventLoopError> {
        tracing::info!(%voting, "Processing registered applications for voting");

        self.block = voting.id;

        let event = self
            .voting_contract
            .event::<RegisterForVoteEvent>()
            .from_block(self.block)
            .address(self.voting_contract.address().into());
        let mut stream = event
            .stream()
            .await
            .map_err(|e| EventLoopError::Recoverable(e.into()))?;
        let mut results = vec![];

        let get_number_of_attendees = self
            .voting_contract
            .method("getNumberOfAttendees", ())
            .map_err(|e| EventLoopError::Recoverable(e.into()))?;
        let number_of_registered_wallets: U256 = get_number_of_attendees
            .call()
            .await
            .map_err(|e| EventLoopError::Recoverable(e.into()))?;

        tracing::info!("Found {number_of_registered_wallets:?} applicants");

        loop {
            if results.len() >= number_of_registered_wallets.as_usize() {
                tracing::info!("Finished processing {} applications.", results.len());
                break;
            }

            match stream.next().await {
                Some(Ok(event)) => {
                    let get_application_state = self
                        .voting_contract
                        .method("getApplicationStateByWallet", event.wallet)
                        .map_err(|e| EventLoopError::Recoverable(e.into()))?;
                    let application_state: ApplicationState = get_application_state
                        .call()
                        .await
                        .map_err(|e| EventLoopError::Recoverable(e.into()))?;

                    tracing::trace!(
                        wallet = %event.wallet, state = %application_state, "Processing application state for user",
                    );

                    if !application_state.requires_update() {
                        results.push(Ok(()));
                        continue;
                    }

                    match self.update_application(event.wallet).await {
                        Ok(receipt) => {
                            self.tx
                                .send((event.wallet, application_state, receipt.transaction_hash))
                                .map_err(|e| {
                                    EventLoopError::Unrecoverable(anyhow::Error::msg(format!(
                                        "Failed to send update confirmation: {e:?}"
                                    )))
                                })?;
                            results.push(Ok(()));
                        }
                        Err(e) => {
                            results.push(Err(e));
                        }
                    }
                }
                Some(Err(e)) => {
                    results.push(Err(anyhow::Error::msg(format!(
                        "Failed to process RegisterForVote event: {e:?}"
                    ))));
                }
                None => {
                    return Err(EventLoopError::Unrecoverable(anyhow::Error::msg(
                        "Subscription to RegisterForVote event ended.",
                    )));
                }
            }
        }

        results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(EventLoopError::Recoverable)
            .map(|_| ())
    }
}
