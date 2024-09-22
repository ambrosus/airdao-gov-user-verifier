use axum::async_trait;
use mongodb::{bson::Document, options::IndexOptions, Collection, IndexModel};

use crate::mongo_client::{MongoClient, MongoCollection, MongoConfig};

/// MongoDB client
#[derive(Clone)]
pub struct UsersDbClient {
    /// Collection being accessed by insert/update/query requests
    pub collection: MongoCollection,
    /// MongoDB query maximum timeout
    pub req_timeout: std::time::Duration,
}

impl UsersDbClient {
    /// Creates mongo client [`MongoClient`] with provided configuration
    pub async fn new(config: &MongoConfig, collection_name: &str) -> anyhow::Result<Self> {
        let collection = Self::init(config, collection_name).await?;

        Ok(Self {
            collection,
            req_timeout: std::time::Duration::from_secs(config.request_timeout),
        })
    }
}

#[async_trait]
impl MongoClient for UsersDbClient {
    fn collection(&self) -> &MongoCollection {
        &self.collection
    }

    async fn initialize_collection(
        db: &mongodb::Database,
        collection_name: &str,
    ) -> anyhow::Result<Collection<Document>> {
        // Get a handle to a collection in the database.
        let collection = db.collection::<Document>(collection_name);

        // Create new collection (if not present in database) and unique index by wallet address
        if !db
            .list_collection_names()
            .await?
            .into_iter()
            .any(|it| it.as_str() == collection_name)
        {
            db.create_collection(collection_name).await?;
        }

        let indexes = collection.list_index_names().await?;

        if !indexes.iter().any(|index| index == "wallet_1") {
            let _ = collection
                .create_index(
                    IndexModel::builder()
                        .keys(bson::doc! {
                            "wallet": 1,
                        })
                        .options(Some(IndexOptions::builder().unique(true).build()))
                        .build(),
                )
                .await?;
        }

        if !indexes.iter().any(|index| index == "email_1") {
            let _ = collection
                .create_index(
                    IndexModel::builder()
                        .keys(bson::doc! {
                            "email": 1,
                        })
                        .options(Some(
                            IndexOptions::builder()
                                .unique(true)
                                .sparse(true)
                                // .partial_filter_expression(bson::doc! {
                                //     "type": "string"
                                // })
                                .build(),
                        ))
                        .build(),
                )
                .await?;
        }

        Ok(collection)
    }
}
