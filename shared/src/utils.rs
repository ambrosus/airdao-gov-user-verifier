use backtrace::Backtrace;
use chrono::{DateTime, TimeZone, Utc};
use config::{self, ConfigError};
use ethabi::{encode, Address, Bytes, Hash, ParamType, Token, Uint};
use ethereum_types::H160;
use k256::{ecdsa::RecoveryId, elliptic_curve::scalar::ScalarPrimitive, Secp256k1};
use log::error;
use serde::de::{self, Deserialize, DeserializeOwned};
use sha3::{Digest, Keccak256};
use std::{panic, path::PathBuf, str::FromStr, thread, time::Duration};

use crate::common::{SBTRequest, WalletSignedMessage, WrappedCid};

const RECOVERABLE_ECDSA_SIGNATURE_LENGTH: usize = 65;

pub async fn load_config<T: DeserializeOwned>(root: &str) -> Result<T, ConfigError> {
    let root = PathBuf::from(root);
    let default = root.join("config/default");
    let custom = root.join("config/custom");

    config::Config::builder()
        // Load default set of configuration
        .add_source(config::File::from(default))
        // Overlay configuration with custom configuration
        .add_source(config::File::from(custom).required(false))
        .build()
        .and_then(|config| config.try_deserialize())
}

pub fn set_heavy_panic() {
    panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::new();

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            error!("Panic occurred: {:?}", s);
        }

        // Get code location
        let location = panic_info.location().unwrap();

        // extract msg
        let msg = match panic_info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<Any>",
            },
        };

        let handle = thread::current();
        let thread_name = handle.name().unwrap_or("<unnamed>");

        error!(
            "thread '{}' panicked at '{}', {}",
            thread_name, location, msg
        );

        error!("{:?}", backtrace);

        std::process::exit(1)
    }));
}

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

/// Deserialize seconds into [`std::time::Duration`]
pub fn de_secs_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: de::Deserializer<'de>,
{
    u64::deserialize(deserializer).map(Duration::from_secs)
}

/// Deserialize seconds timestamp into [`chrono::DateTime`]
pub fn de_secs_timestamp_i64<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: de::Deserializer<'de>,
{
    i64::deserialize(deserializer).and_then(|ts| {
        Utc.timestamp_opt(ts, 0).single().ok_or_else(|| {
            serde::de::Error::custom(format!("Failed to deserialize timestamp: {ts}"))
        })
    })
}

pub fn parse_datetime(ts_bytes: &[u8]) -> Result<DateTime<Utc>, String> {
    <[u8; 8]>::try_from(ts_bytes)
        .map_err(|e| format!("Failed to deserialize DateTime. Error: {e:?}"))
        .and_then(|be_bytes| {
            DateTime::from_timestamp_millis(i64::from_be_bytes(be_bytes))
                .ok_or_else(|| format!("Failed to deserialize DateTime from bytes: {:?}", be_bytes))
        })
}

/// Creates encoded data which contains user's Ethereum wallet address, internal Fractal User Id, timestamps in seconds
/// when request and SBT token will expire.
/// It will be signed and passed later to Issuer smart contract for verification and will result in SBT token mint.
pub fn encode_sbt_request(
    caller: Address,
    user_id: u128,
    req_expires_at: u64,
    sbt_expires_at: u64,
) -> Bytes {
    encode(&[
        Token::Address(caller),
        Token::Uint(user_id.into()),
        Token::Uint(Uint::from(req_expires_at)),
        Token::Uint(Uint::from(sbt_expires_at)),
    ])
}

/// Creates encoded data which contains user's Ethereum wallet address and an eligible TX hash to mint OG SBT.
pub fn encode_og_sbt_request(
    caller: Address,
    og_wallet: Address,
    tx_hash: Hash,
    req_expires_at: u64,
) -> Bytes {
    encode(&[
        Token::Address(caller),
        Token::Address(og_wallet),
        Token::FixedBytes(Vec::from(tx_hash.as_bytes())),
        Token::Uint(Uint::from(req_expires_at)),
    ])
}

/// Creates encoded data which contains user's Ethereum wallet address to mint SNO SBT.
pub fn encode_sno_sbt_request(
    caller: Address,
    sno_wallet: Address,
    server_nodes_manager: Address,
    req_expires_at: u64,
) -> Bytes {
    encode(&[
        Token::Address(caller),
        Token::Address(sno_wallet),
        Token::Address(server_nodes_manager),
        Token::Uint(Uint::from(req_expires_at)),
    ])
}

pub fn decode_sbt_request(data: Bytes) -> Result<SBTRequest, anyhow::Error> {
    let tokens = ethabi::decode(
        &[
            ParamType::Address,
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
        ],
        &data,
    )?;

    match <Vec<Token> as TryInto<[Token; 4]>>::try_into(tokens) {
        Ok(
            [Token::Address(caller), Token::String(user_id), Token::Uint(req_expires_at), Token::Uint(sbt_expires_at)],
        ) => Ok(SBTRequest {
            caller,
            user_id,
            req_expires_at: req_expires_at.as_u64(),
            sbt_expires_at: sbt_expires_at.as_u64(),
        }),
        _ => Err(anyhow::Error::msg("Unknown SBT request format")),
    }
}

pub fn get_eth_address(uncompressed_public_key: &[u8]) -> H160 {
    H160::from_slice(
        &Keccak256::new_with_prefix(&uncompressed_public_key[1..])
            .finalize()
            .as_slice()[12..],
    )
}

pub fn keccak256_hash_message_with_eth_prefix(message: String) -> [u8; 32] {
    Keccak256::new_with_prefix(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    )
    .finalize()
    .into()
}

pub fn recover_eth_address(
    signed_message: WalletSignedMessage,
) -> Result<ethereum_types::Address, anyhow::Error> {
    let decoded_message = String::from_utf8(hex::decode(&signed_message.message)?)?;
    let message_hash = keccak256_hash_message_with_eth_prefix(decoded_message);

    let signature = hex::decode(signed_message.sign)?;
    if signature.len() != RECOVERABLE_ECDSA_SIGNATURE_LENGTH {
        return Err(anyhow::Error::msg("Invalid signature length"));
    }

    let recovery_id = RecoveryId::from_byte((signature[64] as i32 - 27) as u8)
        .ok_or_else(|| anyhow::Error::msg("Invalid reconvery param"))?;

    let signature = k256::ecdsa::Signature::from_scalars(
        ScalarPrimitive::<Secp256k1>::from_slice(&signature[0..32])?.to_bytes(),
        ScalarPrimitive::<Secp256k1>::from_slice(&signature[32..64])?.to_bytes(),
    )?;

    // Recover and verify public key
    let recovered_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)?;

    let wallet = get_eth_address(recovered_key.to_encoded_point(false).as_bytes());

    Ok(wallet)
}

pub fn parse_evm_like_address(address: &str) -> Result<Address, anyhow::Error> {
    let bytes = hex::decode(&address[2..])?;
    let address_bytes = <[u8; 20]>::try_from(bytes.as_slice())?;
    let address = Address::from(&address_bytes);

    Ok(address)
}

pub fn get_checksum_address(address: &Address) -> String {
    // Keccak256 hash the lowercase hex address
    let address = hex::encode(address.as_bytes());
    let hash = Keccak256::new_with_prefix(&address).finalize();

    // Check each character of the hash and uppercase the corresponding character in the address
    address
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if (hash[i / 2] >> (4 * (1 - i % 2))) & 0x0F >= 8 {
                c.to_uppercase().to_string()
            } else {
                c.to_string()
            }
        })
        .collect::<String>()
}

pub fn convert_to_claims_with_expiration(
    obj: impl serde::Serialize,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<serde_json::Value> {
    match serde_json::to_value(&obj)? {
        serde_json::Value::Object(m) => {
            let mut m = m.clone();
            m.insert(
                "exp".to_owned(),
                serde_json::Value::Number(expires_at.timestamp().into()),
            );
            Ok(serde_json::Value::Object(m))
        }
        _ => Err(anyhow::anyhow!("Unable to serialize JWT profile token")),
    }
}

pub fn parse_json_response<T: DeserializeOwned>(text: String) -> Result<T, String> {
    let parsed = serde_json::from_str::<T>(&text);
    if let Ok(parsed) = parsed {
        return Ok(parsed);
    }

    Err(text)
}

pub fn de_opt_cid<'de, D>(deserializer: D) -> Result<Option<WrappedCid>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let data = String::deserialize(deserializer)?;
    let maybe_url = url::Url::from_str(&data);
    let maybe_cid = maybe_url
        .as_ref()
        .ok()
        .and_then(|url| url.path_segments().into_iter().last())
        .and_then(|cid| cid.last())
        .unwrap_or(data.as_str());

    match WrappedCid::new(maybe_cid) {
        Ok(cid) => Ok(Some(cid)),
        // In case of valid url with invalid CID, we assume it is not provided, e.g. `https://ipfs.io/ipfs/undefined`
        Err(_) if maybe_url.is_ok() => Ok(None),
        Err(e) => Err(de::Error::custom(format!(
            "Failed to deserialize Cid from '{data}'. Error: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde::de::IntoDeserializer;
    use std::str::FromStr;

    #[test]
    fn test_de_opt_cid() {
        struct TestCase<'a> {
            input: &'a str,
            expected: Result<Option<WrappedCid>, String>,
        }

        let test_cases = [
            TestCase {
                input: "https://ipfs.io/ipfs/undefined",
                expected: Ok(None),
            },
            TestCase {
                input: "https://ipfs.io/ipfs/QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA23",
                expected: Ok(None),
            },
            TestCase {
                input: "https://ipfs.io/ipfs/QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA2",
                expected: Ok(Some(WrappedCid::new("QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA2").unwrap())),
            },
            TestCase {
                input: "https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                expected: Ok(Some(WrappedCid::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap())),
            },
            TestCase {
                input: "QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA23",
                expected: Err("Failed to deserialize Cid from 'QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA23'. Error: Not a valid Cid".to_owned()),
            },
            TestCase {
                input: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi1",
                expected: Err("Failed to deserialize Cid from 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi1'. Error: Not a valid Cid".to_owned()),
            },
            TestCase {
                input: "QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA2",
                expected: Ok(Some(WrappedCid::new("QmRKs2ZfuwvmZA3QAWmCqrGUjV9pxtBUDP3wuc6iVGnjA2").unwrap())),
            },
            TestCase {
                input: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                expected: Ok(Some(WrappedCid::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap())),
            },
        ];

        for (i, test_case) in test_cases.into_iter().enumerate() {
            assert_eq!(
                de_opt_cid(test_case.input.into_deserializer())
                    .map_err(|e: serde_json::Error| e.to_string()),
                test_case.expected,
                "Test case #{i}"
            );
        }
    }

    #[test]
    fn test_get_eth_address() {
        let uncompressed_pub_key = hex::decode("048cd99ec4cfdafd1c4a5e47396cb8a70ea02200b2e41407172de6148a8a142eded70725272e89bf073e63ef9b491259cfd014f3f3b477d9abf7090e4a6d391b64").unwrap();
        assert_eq!(
            get_eth_address(&uncompressed_pub_key),
            H160::from_str("93a16b4038729f0c498fdd9a70e05fbb33f79a2d").unwrap()
        );
    }

    #[test]
    fn test_encode_sbt_request() {
        let now = Utc::now().timestamp() as u64;
        let req_expires_at = now + 180;
        let sbt_expires_at = now + 86400;
        let caller = Address::random();
        let user_id = uuid::Uuid::from_str("01020304-0506-1122-8877-665544332211")
            .unwrap()
            .as_u128();
        let encoded = encode_sbt_request(caller, user_id, req_expires_at, sbt_expires_at);
        let decoded = ethabi::decode(
            &[
                ethabi::ParamType::Address,
                ethabi::ParamType::Uint(256),
                ethabi::ParamType::Uint(256),
                ethabi::ParamType::Uint(256),
            ],
            &encoded,
        )
        .unwrap();

        assert_matches::assert_matches!(&decoded[0], Token::Address(value) if value == &caller);
        assert_matches::assert_matches!(&decoded[1], Token::Uint(value) if value.as_u128() == user_id);
        assert_matches::assert_matches!(&decoded[2], Token::Uint(value) if value.as_u64() == req_expires_at);
        assert_matches::assert_matches!(&decoded[3], Token::Uint(value) if value.as_u64() == sbt_expires_at);
    }

    #[test]
    fn test_parse_json_response() {
        assert!(super::parse_json_response::<()>("null".to_owned()).is_ok());
        assert_eq!(
            super::parse_json_response::<()>("some error".to_owned()),
            Err("some error".to_owned())
        );
    }
}
