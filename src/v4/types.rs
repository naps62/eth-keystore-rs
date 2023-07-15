use serde::{Deserialize, Serialize};

use crate::{
    common::{KdfType, KdfparamsType},
    utils::{buffer_to_hex, hex_to_buffer},
};

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct CryptoJson {
    pub kdf: Kdf,
    pub cipher: Cipher,
    pub checksum: Checksum,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct Kdf {
    pub function: KdfType,
    pub params: KdfparamsType,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub message: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Checksum {
    pub function: HashFunction,
    pub params: ChecksumParams,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub message: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChecksumParams {}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Types of key derivition functions supported by the Web3 Secret Storage.
pub enum HashFunction {
    Sha256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cipher {
    pub function: String,
    pub params: CipherparamsJson,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub message: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "cipherparams" part of an encrypted JSON keystore.
pub struct CipherparamsJson {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}
