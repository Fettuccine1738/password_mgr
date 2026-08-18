use std::fmt::Display;
use std::path::PathBuf;
use std::vec;

pub mod vc;
use argon2::Params as Argon2Params;
use rand_core::OsRng;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KDF_KEY_LEN: usize = 32;
pub const SALT_NONCE_LEN: usize = SALT_LEN + NONCE_LEN;

///
///
#[derive(Debug)]
pub struct Secret {
    pub id: String,
    pub uname: String,
    pub secret: String,
    pub hint: Option<String>,
}

impl Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "password = ************************************");
        let _ = write!(f, "passphrase = ");
        if let Some(s) = &self.hint {
            write!(f, "{}", s)
        } else {
            write!(f, "<NO Passphrase set for this>")
        }
    }
}

impl Secret {
    pub fn new(id: String, uname: String, secretword: String, hint: Option<String>) -> Self {
        Self {
            id,
            uname,
            secret: secretword,
            hint,
        }
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.uname == other.uname
    }
}

#[derive(Debug)]
pub enum VaultState {
    Locked(LockedVault),
    Unlocked(UnlockedVault),
}

#[derive(Default)]
pub struct VaultFiles(pub Vec<PathBuf>);

#[derive(Debug)]
pub enum UnlockError {
    WrongPassword,
    CorruptStore,
    Io(std::io::Error),
}

use crate::data_struct::vc::VaultContents;
use crate::utils::{aes_gcm_decrypt, aes_gcm_encrypt, generate_fresh_nonce};

/// On-disk, pre-authentication state. Holds only public metadata + ciphertext.
/// No password, no key, no plaintext ever touches this struct.
#[derive(Debug)]
pub struct LockedVault {
    name: String,
    salt: [u8; SALT_LEN],
    kdf_params: Argon2Params,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>, // includes AEAD tag
}

impl LockedVault {
    pub fn new(name: String) -> Self {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);

        Self {
            name,
            salt,
            kdf_params: Argon2Params::DEFAULT,
            nonce,
            ciphertext: vec![],
        }
    }

    pub fn init(name: String, salt: [u8; SALT_LEN], nonce: [u8; NONCE_LEN], cipher: &[u8]) -> Self {
        Self {
            name,
            salt,
            kdf_params: Argon2Params::DEFAULT,
            nonce,
            ciphertext: cipher.to_vec(),
        }
    }

    pub fn unlock(self, password: &str) -> Result<UnlockedVault, (LockedVault, UnlockError)> {
        let key: [u8; 32] =
            crate::utils::derive_key(password.as_bytes(), &self.salt, &self.kdf_params);

        match aes_gcm_decrypt(&key, &self.nonce, &self.ciphertext) {
            Ok(plaintext) => match VaultContents::deserialize(&plaintext) {
                Ok(secrets) => Ok(UnlockedVault {
                    name: self.name,
                    key,
                    salt: self.salt,
                    kdf_params: self.kdf_params,
                    secrets,
                }),
                Err(_) => Err((self, UnlockError::CorruptStore)),
            },
            Err(_) => Err((self, UnlockError::WrongPassword)),
        }
    }
}

/// Post-authentication state. Exists only in memory, never serialized as-is.
#[derive(Debug)]
pub struct UnlockedVault {
    name: String,
    key: [u8; KDF_KEY_LEN], // derived key, kept only for re-encrypting on save
    salt: [u8; SALT_LEN],   // kept so we can reuse or rotate on next save
    kdf_params: Argon2Params,
    secrets: VaultContents, // your actual decrypted usernames/passwords
}

impl UnlockedVault {
    /// Re-encrypts and returns a LockedVault ready to persist.
    pub fn lock(self) -> LockedVault {
        let nonce = generate_fresh_nonce(); // NEVER reuse a nonce with the same key
        let plaintext = self.secrets.serialize();

        let ciphertext = aes_gcm_encrypt(&self.key, &nonce, &plaintext);

        LockedVault {
            name: self.name,
            salt: self.salt,
            kdf_params: self.kdf_params,
            nonce,
            ciphertext,
        }
    }
}
