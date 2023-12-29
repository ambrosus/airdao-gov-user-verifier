use serde::{de, Deserialize};

/// Deserializes private key in hex format into [`k256::SecretKey`]
pub fn de_secp256k1_signing_key<'de, D>(
    deserializer: D,
) -> Result<k256::ecdsa::SigningKey, D::Error>
where
    D: de::Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    let bytes = hex::decode(string)
        .map_err(|err| de::Error::custom(format!("Not supported format: {}", err)))?;
    k256::ecdsa::SigningKey::from_slice(&bytes)
        .map_err(|err| de::Error::custom(format!("Not a private key: {}", err)))
}
