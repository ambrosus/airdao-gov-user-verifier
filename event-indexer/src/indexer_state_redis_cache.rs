use anyhow::Context;
use redis::aio::ConnectionManager;

pub struct IndexerStateRedisCache {
    chain_id: u64,
    pub block_number: u64,
    connection_manager: ConnectionManager,
}

impl IndexerStateRedisCache {
    pub async fn new(
        chain_id: u64,
        redis_url: &str,
        mut block_number: u64,
    ) -> anyhow::Result<Self> {
        // Initialize connection to redis
        let mut connection_manager = redis::Client::open(redis_url)?
            .get_connection_manager()
            .await?;

        if 0 != redis::cmd("EXISTS")
            .arg(format!("indexer.{chain_id}.block_number"))
            .query_async::<u64>(&mut connection_manager)
            .await?
        {
            block_number = redis::cmd("GET")
                .arg(format!("indexer.{}.block_number", chain_id))
                .query_async(&mut connection_manager)
                .await
                .context("Failed to get block_number value from redis")?;

            tracing::info!("Restore indexing from block #{block_number}");
        } else {
            tracing::info!("Start indexing from block #{block_number}");
        }

        Ok(Self {
            chain_id,
            block_number,
            connection_manager,
        })
    }

    pub async fn store_block_number(&mut self, block_number: u64) -> anyhow::Result<()> {
        redis::cmd("SET")
            .arg(format!("indexer.{}.block_number", self.chain_id))
            .arg(block_number)
            .query_async(&mut self.connection_manager)
            .await
            .context("Failed to set block_number value to redis")?;

        self.block_number = block_number;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_indexer_state() -> Result<(), anyhow::Error> {
        let mut state_cache = IndexerStateRedisCache::new(1, "redis://localhost:6379/", 0).await?;

        state_cache.store_block_number(1).await
    }
}
