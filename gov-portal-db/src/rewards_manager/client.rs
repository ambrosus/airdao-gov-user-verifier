use axum::async_trait;
use mongodb::{bson::Document, options::IndexOptions, Collection, IndexModel};

use crate::mongo_client::{MongoClient, MongoCollection, MongoConfig};

/// MongoDB client
#[derive(Clone)]
pub struct RewardsDbClient {
    /// Collection being accessed by insert/update/query requests
    pub collection: MongoCollection,
    /// MongoDB query maximum timeout
    pub req_timeout: std::time::Duration,
}

impl RewardsDbClient {
    /// Creates mongo client [`MongoClient`] with provided configuration
    pub async fn new(mongo_config: &MongoConfig, collection: &str) -> anyhow::Result<Self> {
        let collection = Self::init(mongo_config, collection).await?;

        Ok(Self {
            collection,
            req_timeout: std::time::Duration::from_secs(mongo_config.request_timeout),
        })
    }
}

#[async_trait]
impl MongoClient for RewardsDbClient {
    fn collection(&self) -> &MongoCollection {
        &self.collection
    }

    async fn initialize_collection(
        db: &mongodb::Database,
        collection_name: &str,
    ) -> anyhow::Result<Collection<Document>> {
        // Get a handle to a collection in the database.
        let collection = db.collection::<Document>(collection_name);

        // Create new collection (if not present in database) and unique index by reward id and wallet address
        if !db
            .list_collection_names()
            .await?
            .into_iter()
            .any(|it| it.as_str() == collection_name)
        {
            db.create_collection(collection_name).await?;
        }

        let indexes = collection.list_index_names().await?;

        if !indexes.iter().any(|index| index == "id_1") {
            let _ = collection
                .create_index(
                    IndexModel::builder()
                        .keys(bson::doc! {
                            "id": 1,
                        })
                        .options(Some(IndexOptions::builder().unique(true).build()))
                        .build(),
                )
                .await?;
        }

        Ok(collection)
    }
}
