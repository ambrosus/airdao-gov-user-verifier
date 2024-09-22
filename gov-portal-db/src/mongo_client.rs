use async_trait::async_trait;
use mongodb::{
    bson::Document,
    options::{ClientOptions, FindOptions, InsertOneOptions, UpdateModifications, UpdateOptions},
    results::{InsertOneResult, UpdateResult},
    Client, Collection, Cursor, Database,
};
use serde::Deserialize;
use std::env::VarError;

pub const MONGO_DUPLICATION_ERROR: i32 = 11000;

/// Contains settings to connect MongoDB
#[derive(Clone, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct MongoConfig {
    /// MongoDB connection url, e.g. mongodb+srv://...
    pub url: Option<String>,
    /// MongoDB database name
    pub db: String,
    /// MongoDB query maximum timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
}

/// Default MongoDB query maximum timeout in seconds
fn default_request_timeout() -> u64 {
    10
}

#[derive(Clone)]
pub struct MongoCollection {
    pub db: Database,
    pub inner: Collection<Document>,
}

impl MongoCollection {
    /// Query request from collection by filter
    pub async fn find(
        &self,
        filter: impl Into<Document>,
        find_options: impl Into<Option<FindOptions>>,
    ) -> Result<Cursor<Document>, mongodb::error::Error> {
        self.inner
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
        self.inner.insert_one(doc).with_options(options).await
    }

    /// Updates single document in collection by filter query
    pub async fn update_one(
        &self,
        query: Document,
        update: impl Into<UpdateModifications>,
        options: impl Into<Option<UpdateOptions>>,
    ) -> Result<UpdateResult, mongodb::error::Error> {
        self.inner
            .update_one(query, update)
            .with_options(options)
            .await
    }
}

/// MongoDB client
#[async_trait]
pub trait MongoClient: Send + Sync + 'static {
    async fn init(config: &MongoConfig, collection_name: &str) -> anyhow::Result<MongoCollection> {
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

        let collection = Self::initialize_collection(&db, collection_name).await?;

        Ok(MongoCollection {
            db,
            inner: collection,
        })
    }

    fn collection(&self) -> &MongoCollection;

    async fn server_status(&self) -> Result<bson::Document, mongodb::error::Error> {
        self.collection()
            .db
            .run_command(bson::doc! { "serverStatus": 1 })
            .await
    }

    async fn initialize_collection(
        db: &mongodb::Database,
        collection_name: &str,
    ) -> anyhow::Result<Collection<Document>>;
}
