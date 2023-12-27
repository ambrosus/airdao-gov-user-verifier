use backtrace::Backtrace;
use chrono::{DateTime, NaiveDateTime, Utc};
use config::{self, ConfigError};
use ethabi::{encode, Address, Bytes, ParamType, Token, Uint};
use ethereum_types::H160;
use log::error;
use serde::de::DeserializeOwned;
use sha3::{Digest, Keccak256};
use std::{panic, path::PathBuf, thread};

use crate::common::SBTRequest;

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

pub fn parse_datetime(ts_bytes: &[u8]) -> Result<DateTime<Utc>, String> {
    <[u8; 8]>::try_from(ts_bytes)
        .map_err(|e| format!("Failed to deserialize DateTime. Error: {e:?}"))
        .and_then(|be_bytes| {
            NaiveDateTime::from_timestamp_millis(i64::from_be_bytes(be_bytes))
                .ok_or_else(|| format!("Failed to deserialize DateTime from bytes: {:?}", be_bytes))
        })
        .map(|naive_dt| DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc))
}

/// Creates encoded data which contains user's Ethereum wallet address, internal Fractal User Id, timestamps in seconds
/// when request and SBT token will expire.
/// It will be signed and passed later to Issuer smart contract for verification and will result in SBT token mint.
pub fn encode_sbt_request(
    caller: Address,
    user_id: String,
    req_expires_at: u64,
    sbt_expires_at: u64,
) -> Bytes {
    encode(&[
        Token::Address(caller),
        Token::String(user_id),
        Token::Uint(Uint::from(req_expires_at)),
        Token::Uint(Uint::from(sbt_expires_at)),
    ])
}

pub fn decode_sbt_request(data: Bytes) -> Result<SBTRequest, anyhow::Error> {
    let tokens = ethabi::decode(
        &[
            ParamType::Address,
            ParamType::String,
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

pub fn parse_evm_like_address(address: &str) -> Result<Address, anyhow::Error> {
    let bytes = hex::decode(&address[2..])?;
    let address_bytes = <[u8; 20]>::try_from(bytes.as_slice())?;
    let address = Address::try_from(&address_bytes)?;

    Ok(address)
}

pub fn get_checksum_address(address: &Address) -> String {
    // Keccak256 hash the lowercase hex address
    let address = address.to_string();
    let hash = Keccak256::new_with_prefix(&address).finalize();

    // Check each character of the hash and uppercase the corresponding character in the address
    address
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i > 1 && (hash[i / 2] >> (4 * (1 - i % 2))) & 0x0F >= 8 {
                c.to_uppercase().to_string()
            } else {
                c.to_string()
            }
        })
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::str::FromStr;

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
        let user_id = "SomeUserID";
        let encoded =
            encode_sbt_request(caller, user_id.to_owned(), req_expires_at, sbt_expires_at);
        let decoded = ethabi::decode(
            &[
                ethabi::ParamType::Address,
                ethabi::ParamType::String,
                ethabi::ParamType::Uint(256),
                ethabi::ParamType::Uint(256),
            ],
            &encoded,
        )
        .unwrap();

        assert_matches::assert_matches!(&decoded[0], Token::Address(value) if value == &caller);
        assert_matches::assert_matches!(&decoded[1], Token::String(value) if value.as_str() == user_id);
        assert_matches::assert_matches!(&decoded[2], Token::Uint(value) if value.as_u64() == req_expires_at);
        assert_matches::assert_matches!(&decoded[3], Token::Uint(value) if value.as_u64() == sbt_expires_at);
    }
}
