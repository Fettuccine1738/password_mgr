use std::fmt::{Display, Write};
use std::path::PathBuf;
use std::vec;

pub mod input;
pub mod vc;
use argon2::Params as Argon2Params;
use rand_core::OsRng;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KDF_KEY_LEN: usize = 32;
pub const SALT_NONCE_LEN: usize = SALT_LEN + NONCE_LEN;

///
///
/// TODO: Impl Hash for this, Secrets are owned by VaultContents which may be backed by a Map
#[derive(Eq, Debug, Clone)]
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
    pub fn new(id: String, uname: String, secret: String, hint: Option<String>) -> Self {
        Self {
            id,
            uname,
            secret,
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
#[derive(Debug, Clone)]
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
        let mut nonce = generate_fresh_nonce();
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

    /// Unlocks a newly created instance of `LockedVault`
    /// unlike `unlock`. This cannot fail because this is only a type-state transition
    /// with no extra operations.
    pub fn unlock_new(self, password: &str) -> UnlockedVault {
        let key: [u8; 32] =
            crate::utils::derive_key(password.as_bytes(), &self.salt, &self.kdf_params);
        UnlockedVault {
            name: self.name,
            key,
            salt: self.salt,
            kdf_params: self.kdf_params,
            secrets: VaultContents { secrets: vec![] },
        }
    }

    pub fn unlock(self, password: &str) -> Result<UnlockedVault, (LockedVault, UnlockError)> {
        let key: [u8; 32] =
            crate::utils::derive_key(password.as_bytes(), &self.salt, &self.kdf_params);

        // to decrypt gcm needs the exact keystream (and nonce) used for encryption
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

    pub fn get_salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn get_nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn write<W: Write>(lv: LockedVault, w: W) -> Vec<u8> {
        vec![]
    }
}

/// Post-authentication state. Exists only in memory, never serialized as-is.
#[derive(Debug, Clone)]
pub struct UnlockedVault {
    name: String,
    key: [u8; KDF_KEY_LEN], // derived key, kept only for re-encrypting on save
    salt: [u8; SALT_LEN],   // kept so we can reuse or rotate on next save
    kdf_params: Argon2Params,
    secrets: VaultContents, // your actual decrypted usernames/passwords
}

impl UnlockedVault {
    /// called when instantiating a new Vault, avoiding creating then unlocking 
    /// a `LockedVault`.
    pub fn for_new_vault(name: String, password: &str) -> Self {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = generate_fresh_nonce();
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);

        let key: [u8; 32] =
            crate::utils::derive_key(password.as_bytes(), &salt, &Argon2Params::DEFAULT);
        Self {
            name,
            key,
            salt,
            kdf_params: Argon2Params::DEFAULT,
            secrets: VaultContents { secrets: vec![] },
        }
    }

    /// Re-encrypts and returns a LockedVault ready to persist.
    /// NOTE: Calling lock generates a nonce that will be used to reconstruct
    /// the keysteream for decryption
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
