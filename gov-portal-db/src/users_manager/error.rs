#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("User is already registered")]
    UserAlreadyExist,
    #[error("User is not registered")]
    UserNotFound,
    #[error("DB comminication failure: {0}")]
    DbCommunicationFailure(#[from] mongodb::error::Error),
    #[error("Serialization error: {0}")]
    BsonSerialization(#[from] bson::ser::Error),
    #[error("Deserialization error: {0}")]
    BsonDeserialization(#[from] bson::de::Error),
    #[error("Request timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
}
