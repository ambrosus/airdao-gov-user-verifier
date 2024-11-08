#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Not authorized")]
    Unauthorized,
    #[error("DB comminication failure: {0}")]
    DbCommunicationFailure(#[from] mongodb::error::Error),
    #[error("Serialization error: {0}")]
    BsonSerialization(#[from] bson::ser::Error),
    #[error("Deserialization error: {0}")]
    BsonDeserialization(#[from] bson::de::Error),
    #[error("BSON value access error: {0}")]
    BsonValueAccess(#[from] bson::document::ValueAccessError),
    #[error("Request timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}
