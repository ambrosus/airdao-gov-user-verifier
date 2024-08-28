use std::env::VarError;

use mongodb::{
    bson::Document,
    options::{
        ClientOptions, FindOptions, IndexOptions, InsertOneOptions, UpdateModifications,
        UpdateOptions,
    },
    results::{InsertOneResult, UpdateResult},
    Client, Collection, Cursor, IndexModel,
};
use serde::Deserialize;

/// MongoDB client
#[derive(Clone)]
pub struct MongoClient {
    pub db: mongodb::Database,
    /// Collection being accessed by insert/update/query requests
    pub collection: Collection<Document>,
    /// MongoDB query maximum timeout
    pub req_timeout: std::time::Duration,
}

/// Contains settings to connect MongoDB
#[derive(Clone, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct MongoConfig {
    /// MongoDB connection url, e.g. mongodb+srv://...
    pub url: Option<String>,
    /// MongoDB database name
    pub db: String,
    /// MongoDB user profiles collection name
    pub collection: String,
    /// MongoDB query maximum timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
}

/// Default MongoDB query maximum timeout in seconds
fn default_request_timeout() -> u64 {
    10
}

impl MongoClient {
    /// Creates mongo client [`MongoClient`] with provided configuration
    pub async fn new(config: &MongoConfig) -> anyhow::Result<Self> {
        let conn_url_env: Result<String, VarError> = std::env::var("MONGO_CONN_URL");
        let conn_url = match conn_url_env.as_deref() {
            Ok(conn_url) => Some(conn_url),
            Err(VarError::NotPresent) => config.url.as_deref(),
            Err(VarError::NotUnicode(conn_url)) => {
                return Err(anyhow::Error::msg(format!(
                    "Invalid non-unicode connection url provided `{conn_url:?}`"
                )))
            }
        }
        .ok_or_else(|| anyhow::Error::msg("Mongo connection url is missed"))?;

        // Get a handle to the deployment.
        let inner = ClientOptions::parse(conn_url)
            .await
            .and_then(Client::with_options)?;

        // Get a handle to a database.
        let db = inner.database(&config.db);

        let collection = initialize_collection(&db, &config.collection).await?;

        Ok(Self {
            db,
            collection,
            req_timeout: std::time::Duration::from_secs(config.request_timeout),
        })
    }

    pub async fn server_status(&self) -> Result<bson::Document, mongodb::error::Error> {
        self.db.run_command(bson::doc! { "serverStatus": 1 }).await
    }

    /// Query request from collection by filter
    pub async fn find(
        &self,
        filter: impl Into<Document>,
        find_options: impl Into<Option<FindOptions>>,
    ) -> Result<Cursor<Document>, mongodb::error::Error> {
        self.collection
            .find(filter.into())
            .with_options(find_options)
            .await
    }

    /// Insert single document to collection
    #[allow(unused)]
    pub async fn insert_one(
        &self,
        doc: impl std::borrow::Borrow<Document>,
        options: impl Into<Option<InsertOneOptions>>,
    ) -> Result<InsertOneResult, mongodb::error::Error> {
        self.collection.insert_one(doc).with_options(options).await
    }

    /// Updates single document in collection by filter query
    pub async fn update_one(
        &self,
        query: Document,
        update: impl Into<UpdateModifications>,
        options: impl Into<Option<UpdateOptions>>,
    ) -> Result<UpdateResult, mongodb::error::Error> {
        self.collection
            .update_one(query, update)
            .with_options(options)
            .await
    }
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
