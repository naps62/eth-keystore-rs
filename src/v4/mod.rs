mod types;

use std::{fs::File, io::Write, path::Path};

use digest::{Digest, Update};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    common::{Aes128Ctr, KdfType, KdfparamsType},
    keystore::Keystore,
    KeystoreError,
};

use self::types::{
    Checksum, ChecksumParams, Cipher, CipherparamsJson, CryptoJson, HashFunction, Kdf,
};

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 18u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

impl EthKeystoreV4 {
    pub fn new<R, S>(rng: &mut R, password: S) -> Result<Self, KeystoreError>
    where
        R: Rng + CryptoRng,
        S: AsRef<[u8]>,
    {
        // Generate a random private key.
        let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
        rng.fill_bytes(pk.as_mut_slice());

        Ok(Self::encrypt(rng, &pk, password)?)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EthKeystoreV4 {
    pub crypto: CryptoJson,
    pub description: String,
    pub pubkey: String,
    pub path: String,
    pub uuid: Uuid,
    pub version: u8,
}

impl Keystore for EthKeystoreV4 {
    fn decrypt<S>(&self, password: S) -> Result<Vec<u8>, KeystoreError>
    where
        S: AsRef<[u8]>,
    {
        // Derive the key.
        let key = match self.crypto.kdf.params {
            KdfparamsType::Pbkdf2 {
                c,
                dklen,
                prf: _,
                ref salt,
            } => {
                let mut key = vec![0u8; dklen as usize];
                pbkdf2::<Hmac<Sha256>>(password.as_ref(), salt, c, key.as_mut_slice());
                key
            }
            KdfparamsType::Scrypt {
                dklen,
                n,
                p,
                r,
                ref salt,
            } => {
                let mut key = vec![0u8; dklen as usize];
                let log_n = (n as f32).log2() as u8;
                let scrypt_params = ScryptParams::new(log_n, r, p)?;
                scrypt(password.as_ref(), salt, &scrypt_params, key.as_mut_slice())?;
                key
            }
        };

        // Derive the MAC from the derived key and ciphertext.
        let derived_mac = Sha256::new()
            .chain(&key[16..32])
            .chain(&self.crypto.cipher.message)
            .finalize();

        if derived_mac.as_slice() != self.crypto.checksum.message.as_slice() {
            return Err(KeystoreError::MacMismatch);
        }

        // Decrypt the private key bytes using AES-128-CTR
        let decryptor = Aes128Ctr::new(&key[..16], &self.crypto.cipher.params.iv[..16])
            .expect("invalid length");

        let mut pk = self.crypto.cipher.message.clone();
        decryptor.apply_keystream(&mut pk);

        Ok(pk)
    }

    fn encrypt<R, B, S>(rng: &mut R, pk: B, password: S) -> Result<Self, KeystoreError>
    where
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let bls_sk = match blst::min_pk::SecretKey::from_bytes(pk.as_ref()) {
            Ok(sk) => sk,
            Err(e) => return Err(KeystoreError::BLSError(e)),
        };

        let bls_pk = bls_sk.sk_to_pk().compress();
        let pubkey = hex::encode(bls_pk);

        // Generate a random salt.
        let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
        rng.fill_bytes(salt.as_mut_slice());

        // Derive the key.
        let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
        )?;
        scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

        // Encrypt the private key using AES-128-CTR.
        let mut iv = vec![0u8; DEFAULT_IV_SIZE];
        rng.fill_bytes(iv.as_mut_slice());

        let encryptor = Aes128Ctr::new(&key[..16], &iv[..16]).expect("invalid length");

        let mut ciphertext = pk.as_ref().to_vec();
        encryptor.apply_keystream(&mut ciphertext);

        // Calculate the MAC.
        let mac = Sha256::new()
            .chain(&key[16..32])
            .chain(&ciphertext)
            .finalize();

        let version = 4;
        let path = String::from(""); // Path is not currently derived
        let description = String::from("Version 4 BLS keystore");

        // Construct and serialize the encrypted JSON keystore.
        Ok(Self {
            description,
            uuid: Uuid::new_v4(),
            pubkey,
            path,
            version: 4,
            crypto: CryptoJson {
                kdf: Kdf {
                    function: KdfType::Scrypt,
                    params: KdfparamsType::Scrypt {
                        dklen: DEFAULT_KDF_PARAMS_DKLEN,
                        n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                        p: DEFAULT_KDF_PARAMS_P,
                        r: DEFAULT_KDF_PARAMS_R,
                        salt,
                    },
                    message: vec![],
                },
                checksum: Checksum {
                    function: HashFunction::Sha256,
                    params: ChecksumParams {},
                    message: mac.to_vec(),
                },
                cipher: Cipher {
                    function: String::from(DEFAULT_CIPHER),
                    params: CipherparamsJson { iv },
                    message: ciphertext.to_vec(),
                },
            },
        })
    }

    fn save_to_file<P>(&self, dir: P, name: Option<&str>) -> Result<(), KeystoreError>
    where
        P: AsRef<Path>,
    {
        // If a file name is not specified for the keystore, simply use the strigified uuid.
        let name = if let Some(name) = name {
            name.to_string()
        } else {
            self.uuid.to_string()
        };
        let contents = serde_json::to_string(self)?;

        // Create a file in write-only mode, to store the encrypted JSON keystore.
        let mut file = File::create(dir.as_ref().join(name))?;
        file.write_all(contents.as_bytes())?;

        Ok(())
    }
}

pub fn encrypt_key<P, R, B, S>(
    dir: P,
    rng: &mut R,
    pk: B,
    password: S,
    name: Option<&str>,
) -> Result<String, KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let keystore = EthKeystoreV4::encrypt(rng, pk, password)?;

    // If a file name is not specified for the keystore, simply use the strigified uuid.
    let name = if let Some(name) = name {
        name.to_string()
    } else {
        keystore.uuid.to_string()
    };

    let version = 4;
    let path = String::from(""); // Path is not currently derived
    let description = String::from("Version 4 BLS keystore");

    let contents = serde_json::to_string(&keystore)?;

    // Create a file in write-only mode, to store the encrypted JSON keystore.
    let mut file = File::create(dir.as_ref().join(name))?;
    file.write_all(contents.as_bytes())?;

    Ok(keystore.uuid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use uuid::Uuid;

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_pbkdf2() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335

        let data = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }"#;
        let keystore: EthKeystoreV4 = serde_json::from_str(data).unwrap();

        // Check outer level
        assert_eq!(
            keystore.uuid,
            Uuid::parse_str("64625def-3331-4eea-ab6f-782f3ed16a83").unwrap()
        );
        assert_eq!(
            keystore.description,
            "This is a test keystore that uses PBKDF2 to secure the secret.".to_string()
        );
        assert_eq!(
            keystore.pubkey,
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()
        );
        assert_eq!(keystore.path, "m/12381/60/0/0".to_string());

        // Check Cipher
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipher.params.iv,
            Vec::from_hex("264daa3f303d7259501c93d997d84fe6").unwrap()
        );
        assert_eq!(
            keystore.crypto.cipher.message,
            Vec::from_hex("cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad")
                .unwrap()
        );

        // Check KDF
        assert_eq!(keystore.crypto.kdf.function, KdfType::Pbkdf2);
        assert_eq!(
            keystore.crypto.kdf.params,
            KdfparamsType::Pbkdf2 {
                c: 262144,
                dklen: 32,
                prf: String::from("hmac-sha256"),
                salt: Vec::from_hex(
                    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                )
                .unwrap(),
            }
        );
        assert_eq!(keystore.crypto.kdf.message, Vec::from_hex("").unwrap());

        // Test Checksum
        assert_eq!(
            keystore.crypto.checksum.message,
            Vec::from_hex("8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1")
                .unwrap()
        );

        assert_eq!(keystore.crypto.checksum.function, HashFunction::Sha256);
    }

    #[test]
    fn test_deserialize_kdf() {
        let data = r#"
        {
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        }"#;
        let _kdf: Kdf = serde_json::from_str(data).unwrap();
    }

    #[test]
    fn test_deserialize_checksum() {
        let data = r#"
        {
            "function": "sha256",
            "params": {},
            "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
        }"#;
        let _kdf: Checksum = serde_json::from_str(data).unwrap();
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_scrypt() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335

        use hex::FromHex;
        let data = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        }"#;
        let keystore: EthKeystoreV4 = serde_json::from_str(data).unwrap();

        // Check outer level
        assert_eq!(
            keystore.uuid,
            Uuid::parse_str("1d85ae20-35c5-4611-98e8-aa14a633906f").unwrap()
        );
        assert_eq!(
            keystore.description,
            "This is a test keystore that uses scrypt to secure the secret.".to_string()
        );
        assert_eq!(
            keystore.pubkey,
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()
        );
        assert_eq!(keystore.path, "m/12381/60/3141592653/589793238".to_string());

        // Check Cipher
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipher.params.iv,
            Vec::from_hex("264daa3f303d7259501c93d997d84fe6").unwrap()
        );
        assert_eq!(
            keystore.crypto.cipher.message,
            Vec::from_hex("06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f")
                .unwrap()
        );
        // Check KDF
        assert_eq!(keystore.crypto.kdf.function, KdfType::Scrypt);
        assert_eq!(
            keystore.crypto.kdf.params,
            KdfparamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 1,
                r: 8,
                salt: Vec::from_hex(
                    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                )
                .unwrap(),
            }
        );
        assert_eq!(keystore.crypto.kdf.message, Vec::from_hex("").unwrap());

        // Test Checksum
        assert_eq!(
            keystore.crypto.checksum.message,
            Vec::from_hex("d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484")
                .unwrap()
        );

        assert_eq!(keystore.crypto.checksum.function, HashFunction::Sha256);
    }
}
