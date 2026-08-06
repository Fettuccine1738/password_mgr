use std::collections::HashMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};

use crate::utils::verify_password;

///
///
#[derive(Debug)]
pub struct Password {
    id: String,
    uname: String,
    hashed_pass: String,
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
            hashed_pass: hashed_password,
            descriptor,
        }
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.uname == other.uname
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
    hashed_pass: String,
    store: HashMap<String, Password>,
}

impl VaultState {
    pub fn new(name: String, hashed_pass: String, store: HashMap<String, Password>) -> Self {
        Self {
            name,
            hashed_pass,
            store,
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn change_password() -> bool {
        todo!()
    }
}

impl LockedVault {
    pub fn new(name: String, hashed_pass: String, store: HashMap<String, Password>) -> Self {
        Self {
            state: VaultState {
                name,
                hashed_pass,
                store,
            },
        }
    }

    pub fn unlock(self, password: String) -> Result<UnlockedVault, LockedVault> {
        if verify_password(&password, &self.state.hashed_pass) {
            Ok(UnlockedVault { state: self.state })
        } else {
            Err(self)
        }
    }
}

impl UnlockedVault {
    pub fn init_no_store(name: String, hashed_pass: String) -> Self {
        Self {
            state: VaultState {
                name,
                hashed_pass,
                store: HashMap::new(),
            },
        }
    }
    pub fn new(name: String, hashed_pass: String, store: HashMap<String, Password>) -> Self {
        Self {
            state: VaultState {
                name,
                hashed_pass,
                store,
            },
        }
    }

    pub fn lock(self, password: String) -> Result<LockedVault, UnlockedVault> {
        if verify_password(&password, &self.state.hashed_pass) {
            Ok(LockedVault { state: self.state })
        } else {
            Err(self)
        }
    }

    pub fn store_mut(&self) -> &mut HashMap<String, Password> {
        todo!()
    }

    pub fn store(&self) -> &HashMap<String, Password> {
        &self.state.store
    }
}

#[derive(Default)]
pub struct VaultFiles(pub Vec<PathBuf>);
