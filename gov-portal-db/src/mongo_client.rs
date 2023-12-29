use mongodb::{
    bson::Document,
    options::{
        ClientOptions, ConnectionString, FindOptions, InsertOneOptions, UpdateModifications,
        UpdateOptions,
    },
    results::{InsertOneResult, UpdateResult},
    Client, Collection, Cursor,
};
use serde::Deserialize;

#[derive(Clone)]
pub struct MongoClient {
    collection: Collection<Document>,
    pub req_timeout: std::time::Duration,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct MongoConfig {
    /// MongoDB connection url, e.g. mongodb+srv://...
    #[serde(default)]
    pub url: Option<ConnectionString>,
    /// MongoDB database name
    pub db_name: String,
    /// MongoDB user profiles collection name
    pub collection_name: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
}

fn default_request_timeout() -> u64 {
    10_000
}

impl MongoClient {
    pub async fn init(mut config: MongoConfig) -> anyhow::Result<Self> {
        if let Ok(conn_str) = std::env::var("MONGO_CONN_URL") {
            // Parse a connection string into an options struct.
            config.url = Some(ConnectionString::parse(conn_str)?);
        }

        let client_options = ClientOptions::parse_connection_string(
            config
                .url
                .ok_or_else(|| anyhow::Error::msg("Mongo connection url is missed"))?,
        )
        .await?;

        // Get a handle to the deployment.
        let inner = Client::with_options(client_options)?;

        // Get a handle to a database.
        let db = inner.database(&config.db_name);

        // Get a handle to a collection in the database.
        let collection = db.collection::<Document>(&config.collection_name);

        Ok(Self {
            collection,
            req_timeout: std::time::Duration::from_millis(config.request_timeout),
        })
    }

    pub async fn find(
        &self,
        filter: impl Into<Option<Document>>,
        find_options: impl Into<Option<FindOptions>>,
    ) -> Result<Cursor<Document>, mongodb::error::Error> {
        self.collection.find(filter, find_options).await
    }

    pub async fn insert_one(
        &self,
        doc: impl std::borrow::Borrow<Document>,
        options: impl Into<Option<InsertOneOptions>>,
    ) -> Result<InsertOneResult, mongodb::error::Error> {
        self.collection.insert_one(doc, options).await
    }

    pub async fn update_one(
        &self,
        query: Document,
        update: impl Into<UpdateModifications>,
        options: impl Into<Option<UpdateOptions>>,
    ) -> Result<UpdateResult, mongodb::error::Error> {
        self.collection.update_one(query, update, options).await
    }
}
