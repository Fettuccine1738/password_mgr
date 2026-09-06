use std::fmt::Write;
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

#[derive(Debug, Default)]
pub enum VaultState {
    Locked(LockedVault),
    Unlocked(UnlockedVault),
    #[default]
    Limbo,
}

impl VaultState {
    pub fn transition(self, input_src: &mut impl InputSource) -> Self {
        match self {
            Self::Locked(locked) => {
                let passw = input_src.read_password("Enter password: ");
                match locked.unlock(&passw) {
                    Ok(uv) => Self::Unlocked(uv),
                    Err((lv, _)) => Self::Locked(lv),
                }
            }
            Self::Unlocked(u) => Self::Locked(u.lock()),
            Self::Limbo => Self::Limbo,
        }
    }

    pub fn lock_and_write(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Unlocked(uv) => {
                let filename = uv.get_name();
                let locked = uv.snapshot();
                super::write_to_disk(filename, &locked)?;
                Ok(())
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Vault is not unlocked",
            )),
        }
    }

    // returns false if secret was not added, true if it was added or updated
    pub fn add_password(&mut self, secret: Secret, input_src: &mut impl InputSource) -> bool {
        match self {
            Self::Unlocked(ul) => {
                // verify if secret already exists, if so prompt for update
                if let Some(existing_secret) =
                    ul.fetch_secret_for_website_mut(secret.website.as_ref().unwrap())
                {
                    // TODO : put this in a retry loop, if the user enters invalid input, we can retry
                    // let update = <ErrCatchingRetry<Result<bool, ()>> as retry::Retry<bool>>::retry(&mut rtry, || {
                    //     Ok(response)
                    // });
                    if input_src.prompt_for_confirmation(
                        "Secret already exists for this website. Do you want to update it? (y/n): ",
                    ) {
                        *existing_secret = secret;
                        true
                    } else {
                        false
                    }
                } else {
                    ul.add_secret(secret);
                    return true;
                }
            }
            _ => false,
        }
    }

    pub fn fetch_password_for_website(
        &mut self,
        input_src: &mut impl InputSource,
    ) -> Option<&Secret> {
        match self {
            Self::Unlocked(ul) => {
                let website = input_src.read_line("Enter website (without https://)");
                return ul.fetch_secret_for_website(&website);
            }
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct VaultFiles(pub Vec<PathBuf>);

#[derive(Debug)]
pub enum UnlockError {
    WrongPassword,
    CorruptStore,
    Io(std::io::Error),
}

#[derive(Debug)]
pub enum SignInError {
    NotFound,
    Unlock(LockedVault, UnlockError),
}

use crate::data_struct::input::{InputSource, InputSourceImpl};
use crate::data_struct::vc::{Secret, VaultContents};
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
            secrets: VaultContents { cntnt: vec![] },
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

    pub fn get_cipher(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn write<W: Write>(_lv: LockedVault, _w: W) -> Vec<u8> {
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
    pub fn get_secrets_count(&self) -> usize {
        self.secrets.cntnt.len()
    }

    pub fn add_secret(&mut self, s: Secret) {
        // we previously checked if the secret already exists, so we can just push it to the vector
        // fetch_secret_for_website will return a mutable reference to the existing secret if it exists, so we can update it in place

        // let idx = {
        //     let mut idx = 0;
        //     for  scrt in &self.secrets.cntnt {
        //         if *scrt == s {
        //             break;
        //         }
        //         idx += 1;
        //     }
        //     idx
        // };

        // if idx < self.secrets.cntnt.len() {
        //     self.secrets.cntnt[idx] = s;
        //     return true;
        // }
        // self.secrets.cntnt.push(s);
        // false
        self.secrets.cntnt.push(s);
    }

    // TODO: Use hash for O(1)
    // we must maintain the invariant that a website can only have one secret associated with it,
    // so we can use the website as a key to fetch the secret. Also, we can use the website as a key to update the secret.
    pub fn fetch_secret_for_website(&self, website: &str) -> Option<&Secret> {
        for s in &self.secrets.cntnt {
            if s.website.is_none() {
                continue;
            }

            if s.website.as_ref().unwrap() == website {
                return Some(s);
            }
        }
        None
    }

    pub fn fetch_secret_for_website_mut(&mut self, website: &str) -> Option<&mut Secret> {
        for s in &mut self.secrets.cntnt {
            if s.website.is_none() {
                continue;
            }

            if s.website.as_ref().unwrap() == website {
                return Some(s);
            }
        }
        None
    }

    pub fn update_secret_at(&mut self, idx: usize, s: Secret) -> Result<(), String> {
        if idx >= self.secrets.cntnt.len() {
            return Err("Index out of bounds".to_string());
        }
        self.secrets.cntnt[idx] = s;
        Ok(())
    }

    // TODO: Use hash for O(1) and return a reference to the secret instead of cloning it.
    // this fetches all secrets that match the given string, either in the username or website.
    pub fn fetch_secret<'a>(&self, like: &str) -> Vec<Secret> {
        let like = like.to_lowercase();
        let mut found = vec![];
        for s in &self.secrets.cntnt {
            if (s.uname.is_some() && s.uname.as_ref().unwrap().contains(&like))
                || (s.website.is_some() && s.website.as_ref().unwrap().contains(&like))
            {
                found.push(s.clone()); // TODO: return a reference instead of cloning
            }
        }
        found
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

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
            secrets: VaultContents { cntnt: vec![] },
        }
    }

    /// Produces a locked snapshot for persisting, without consuming self —
    /// the vault stays unlocked in memory for further edits.
    pub fn snapshot(&self) -> LockedVault {
        let nonce = generate_fresh_nonce(); // never reuse, even across snapshots
        let plaintext = self.secrets.serialize();
        let ciphertext = aes_gcm_encrypt(&self.key, &nonce, &plaintext);

        LockedVault {
            name: self.name.clone(),
            salt: self.salt,
            kdf_params: self.kdf_params.clone(),
            nonce,
            ciphertext,
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
