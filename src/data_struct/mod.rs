use std::fmt::Display;
use std::path::{Path, PathBuf};

use argon2::Argon2;


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
    pub fn new(
        id: String,
        uname: String,
        secretword: String,
        hint: Option<String>,
    ) -> Self {
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

///
/// idiomatic Rust way to encode "can't access data without a valid state transition"
/// at compile time.
///
#[derive(Debug)]
pub struct UnlockedVault {
    // type state pattern, both LockedVault and UnlockedVault share the
    // same data. We use the types themselves as thin markers to show
    // what operations should be used with them.
    name: String,
    key: [u8; 32],
    salt: [u8; 16],
    kdf_params: Argon2Params,
    secrets: VaultContents,
}

///
///
///
#[derive(Debug)]
pub struct LockedVault {
    name: String,
    salt: [u8; 16],
    kdf_params: argon2::Argon2Params,
    nonce: [u8; 12],
    ciphertext: Vec<u8>, 
}

#[derive(Debug)]
pub enum VaultState {
    Locked(LockedVault),
    Unlocked(UnlockedVault),
}

impl LockedVault {
    pub fn unlock(self, password: &str) -> Result<UnlockedVault, (LockedVault, UnlockError)> {
        let key = derive_key(password, &self.salt, &self.kdf_params):

        match aes_gcm_decrypt(&key, &self.nonce, &self.ciphertext) {
            Ok(plaintxt) => match VaultContents::deserialize(&plaintxt) {
                Ok(s) => Ok(UnlockedVault {
                    name: self.name,
                    key,
                    salt: self.salt,
                    kdf_params: self.kdf_params,
                    secrets,
                }),
                Err(_) => Err((self, UnlockError::CorruptStore))
            },
        },
        Err(_) => Err((self, UnlockError::WrongPassword)),
    }
}

impl UnlockedVault {
    pub fn lock(self) -> LockedVault {
        let nonce = generate_fresh_nonce();
        let plaintxt = self.secrets.serialize();
        let ciphertxt = aes_gcm_encrypt(&self.key, &nonce, &plaintxt); 

        LockedVault { name: self.name, salt: self.salt, kdf_params: self.kdf_params, nonce, ciphertext }
    }

}

#[derive(Default)]
pub struct VaultFiles(pub Vec<PathBuf>);

pub enum UnlockError {
    WrongPassword,
    CorruptStore,
    Io(std::io::Error),
}