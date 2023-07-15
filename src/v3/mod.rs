mod types;

use std::{fs::File, io::Write, path::Path};

use digest::{Digest, Update};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::Keccak256;
use uuid::Uuid;

use crate::{
    common::{Aes128Ctr, KdfType, KdfparamsType},
    keystore::Keystore,
    KeystoreError,
};

#[cfg(feature = "geth-compat")]
use crate::utils::geth_compat::address_from_pk;
#[cfg(feature = "geth-compat")]
use ethereum_types::H160 as Address;

pub use types::*;

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

#[derive(Debug, Deserialize, Serialize)]
/// This struct represents the deserialized form of an encrypted JSON keystore based on the
/// [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
pub struct EthKeystoreV3 {
    #[cfg(feature = "geth-compat")]
    pub address: Address,

    pub crypto: CryptoJson,
    pub id: Uuid,
}

impl EthKeystoreV3 {
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

impl Keystore for EthKeystoreV3 {
    fn decrypt<S>(&self, password: S) -> Result<Vec<u8>, KeystoreError>
    where
        S: AsRef<[u8]>,
    {
        // Derive the key.
        let key = match self.crypto.kdfparams {
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
        let derived_mac = Keccak256::new()
            .chain(&key[16..32])
            .chain(&self.crypto.ciphertext)
            .finalize();

        if derived_mac.as_slice() != self.crypto.mac.as_slice() {
            return Err(KeystoreError::MacMismatch);
        }

        // Decrypt the private key bytes using AES-128-CTR
        let decryptor =
            Aes128Ctr::new(&key[..16], &self.crypto.cipherparams.iv[..16]).expect("invalid length");

        let mut pk = self.crypto.ciphertext.clone();
        decryptor.apply_keystream(&mut pk);

        Ok(pk)
    }

    fn encrypt<R, B, S>(rng: &mut R, pk: B, password: S) -> Result<Self, KeystoreError>
    where
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
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
        let mac = Keccak256::new()
            .chain(&key[16..32])
            .chain(&ciphertext)
            .finalize();

        // Construct and serialize the encrypted JSON keystore.
        Ok(Self {
            id: Uuid::new_v4(),
            // version: 3,
            crypto: CryptoJson {
                cipher: String::from(DEFAULT_CIPHER),
                cipherparams: CipherparamsJson { iv },
                ciphertext: ciphertext.to_vec(),
                kdf: KdfType::Scrypt,
                kdfparams: KdfparamsType::Scrypt {
                    dklen: DEFAULT_KDF_PARAMS_DKLEN,
                    n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                    p: DEFAULT_KDF_PARAMS_P,
                    r: DEFAULT_KDF_PARAMS_R,
                    salt,
                },
                mac: mac.to_vec(),
            },
            #[cfg(feature = "geth-compat")]
            address: address_from_pk(&pk)?,
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
            self.id.to_string()
        };
        let contents = serde_json::to_string(self)?;

        // Create a file in write-only mode, to store the encrypted JSON keystore.
        let mut file = File::create(dir.as_ref().join(name))?;
        file.write_all(contents.as_bytes())?;

        Ok(())
    }
}

pub fn new<P, R, S>(
    dir: P,
    rng: &mut R,
    password: S,
    name: Option<&str>,
) -> Result<(Vec<u8>, String), KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    // Generate a random private key.
    let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(pk.as_mut_slice());

    let name = encrypt_key(dir, rng, &pk, password, name)?;
    Ok((pk, name))
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
    let keystore = EthKeystoreV3::encrypt(rng, pk, password)?;

    // If a file name is not specified for the keystore, simply use the strigified uuid.
    let name = if let Some(name) = name {
        name.to_string()
    } else {
        keystore.id.to_string()
    };
    let contents = serde_json::to_string(&keystore)?;

    // Create a file in write-only mode, to store the encrypted JSON keystore.
    let mut file = File::create(dir.as_ref().join(name))?;
    file.write_all(contents.as_bytes())?;

    Ok(keystore.id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "geth-compat")]
    use hex::FromHex;

    #[cfg(feature = "geth-compat")]
    #[test]
    fn deserialize_geth_compat_keystore() {
        let data = r#"
        {
            "address": "00000398232e2064f896018496b4b44b3d62751f",
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "4f784cd629a7caf34b488e36fb96aad8a8f943a6ce31c7deab950c5e3a5b1c43",
                "cipherparams": {
                    "iv": "76f07196b3c94f25b8f34d869493f640"
                },
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "1e7be4ce8351dd1710b0885438414b1748a81f1af510eda11e4d1f99c8d43975"
                },
                "mac": "5b5433575a2418c1c813337a88b4099baa2f534e5dabeba86979d538c1f594d8"
            },
            "id": "6c4485f3-3cc0-4081-848e-8bf489f2c262",
            "version": 3
        }"#;
        let keystore: EthKeystoreV3 = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.address.as_bytes().to_vec(),
            hex::decode("00000398232e2064f896018496b4b44b3d62751f").unwrap()
        );
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_pbkdf2() {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
                },
                "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
                "kdf" : "pbkdf2",
                "kdfparams" : {
                    "c" : 262144,
                    "dklen" : 32,
                    "prf" : "hmac-sha256",
                    "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                },
                "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
            },
            "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version" : 3
        }"#;
        let keystore: EthKeystoreV3 = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap()
        );
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            Vec::from_hex("6087dab2f9fdbbfaddc31a909735c1e6").unwrap()
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            Vec::from_hex("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46")
                .unwrap()
        );
        assert_eq!(keystore.crypto.kdf, KdfType::Pbkdf2);
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfparamsType::Pbkdf2 {
                c: 262144,
                dklen: 32,
                prf: String::from("hmac-sha256"),
                salt: Vec::from_hex(
                    "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                )
                .unwrap(),
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            Vec::from_hex("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                .unwrap()
        );
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_scrypt() {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "83dbcc02d8ccb40e466191a123791e0e"
                },
                "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                "kdf" : "scrypt",
                "kdfparams" : {
                    "dklen" : 32,
                    "n" : 262144,
                    "p" : 8,
                    "r" : 1,
                    "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                },
                "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
            },
            "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version" : 3
        }"#;
        let keystore: EthKeystoreV3 = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap()
        );
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            Vec::from_hex("83dbcc02d8ccb40e466191a123791e0e").unwrap()
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            Vec::from_hex("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c")
                .unwrap()
        );
        assert_eq!(keystore.crypto.kdf, KdfType::Scrypt);
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfparamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 8,
                r: 1,
                salt: Vec::from_hex(
                    "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                )
                .unwrap(),
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            Vec::from_hex("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")
                .unwrap()
        );
    }
}
