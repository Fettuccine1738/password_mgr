use std::collections::HashMap;
use std::fmt::Display;

use crate::utils::validate_key;

///
///
#[derive(Debug)]
pub struct Password {
    id: String,
    uname: String,
    password: String,
    descriptor: Option<String>,
}

impl Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "password = ************************************");
        let _ = write!(f, "passphrase = ");
        if let Some(s) = &self.descriptor {
            write!(f, "{}", s)
        } else {
            write!(f, "<NO Passphrase set for this>")
        }
    }
}

impl Password {
    pub fn new(
        id: String,
        uname: String,
        hashed_password: String,
        descriptor: Option<String>,
    ) -> Self {
        Self {
            id,
            uname,
            password: hashed_password,
            descriptor,
        }
    }
}

///
/// idiomatic Rust way to encode "can't access data without a valid state transition"
/// at compile time.
///
pub struct LockedVault {
    // type state pattern, both LockedVault and UnlockedVault share the
    // same data. We use the types themselves as thin markers to show
    // what operations should be used with them.
    state: VaultState,
}

///
///
pub struct UnlockedVault {
    state: VaultState,
}

pub struct VaultState {
    name: String,
    password: String,
    store: HashMap<String, Password>,
}

impl VaultState {
    pub fn new(name: String, password: String, store: HashMap<String, Password>) -> Self {
        Self {
            name,
            password,
            store,
        }
    }
}

impl LockedVault {
    pub fn unlock(self, key: String) -> Result<UnlockedVault, LockedVault> {
        if validate_key(&key, &self.state.password) {
            Ok(UnlockedVault { state: self.state })
        } else {
            Err(self)
        }
    }
}

impl UnlockedVault {
    pub fn new(name: String, password: String, store: HashMap<String, Password>) -> Self {
        Self {
            state: VaultState {
                name,
                password,
                store,
            },
        }
    }

    pub fn lock(self, key: String) -> Result<LockedVault, UnlockedVault> {
        if validate_key(&key, &self.state.password) {
            Ok(LockedVault { state: self.state })
        } else {
            Err(self)
        }
    }
}
