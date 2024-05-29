use ethers::{contract::ContractInstance, providers::Middleware};
use std::{borrow::Borrow, fmt::Debug};

pub async fn list_sbt<B: Clone + Borrow<M>, M: Middleware + Debug + 'static>(
    contract: &ContractInstance<B, M>,
) -> anyhow::Result<Vec<(ethereum_types::Address, ethereum_types::U256)>> {
    contract
        .method::<_, Vec<(ethereum_types::Address, ethereum_types::U256)>>("listSBT", ())?
        .call()
        .await
        .map_err(anyhow::Error::from)
}
