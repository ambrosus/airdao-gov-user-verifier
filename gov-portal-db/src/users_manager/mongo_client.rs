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

#[derive(Clone)]
pub struct MongoClient {
    collection: Collection<Document>,
    pub req_timeout: std::time::Duration,
}

#[derive(Clone, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct MongoConfig {
    /// MongoDB connection url, e.g. mongodb+srv://...
    pub url: Option<String>,
    /// MongoDB database name
    pub db: String,
    /// MongoDB user profiles collection name
    pub collection: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
}

fn default_request_timeout() -> u64 {
    10_000
}

impl MongoClient {
    pub async fn init(config: &MongoConfig) -> anyhow::Result<Self> {
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

        let collection = initialize_collection(&inner, &config.db, &config.collection).await?;

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

async fn initialize_collection(
    client: &Client,
    db_name: &str,
    collection_name: &str,
) -> anyhow::Result<Collection<Document>> {
    // if client
    //     .list_database_names(None, None)
    //     .await?
    //     .into_iter()
    //     .find(|it| it.as_str() == db_name)
    //     .is_none()
    // {
    //     return Err(anyhow::anyhow!("DB `{db_name}` is not initialized!"));
    // }

    // Get a handle to a database.
    let db = client.database(db_name);

    // Get a handle to a collection in the database.
    let collection = db.collection::<Document>(collection_name);

    if db
        .list_collection_names(None)
        .await?
        .into_iter()
        .any(|it| it.as_str() == collection_name)
    {
        db.create_collection(collection_name, None).await?;

        println!(
            "{:?}",
            collection
                .create_index(
                    IndexModel::builder()
                        .keys(bson::doc! {
                            "wallet": 1,
                        })
                        .options(Some(IndexOptions::builder().unique(true).build()))
                        .build(),
                    None,
                )
                .await?
        );
    }

    Ok(collection)
}
