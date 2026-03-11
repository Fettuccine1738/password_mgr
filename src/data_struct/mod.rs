pub struct Password {
    password: String, 
    info: Option<String>,
    passphrase: Option<String>
}

use std::fmt::Display;

impl Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "info::");
        if let Some(s) = &self.info {
            let _ = write!(f, "{}",s);
        } 
        let _ = write!(f, "password = ************************************");
        let _ = write!(f, "passphrase = ");
        if let Some(s) = &self.passphrase {
            write!(f, "{}",s)
        } else {
            write!(f, "<NO Passphrase set for this>")
        } 
    }
}

impl Password {
    pub fn new(hashed_password: String, passphrase: Option<String>) -> Self {
        Self {
            password: hashed_password,
            passphrase: passphrase,
            info: Self::generate_info()
        }
    }


    fn generate_info() -> Option<String> {
        todo!()
    }
}

pub struct LockedPasswordManager {
}

pub struct UnlockedPasswordManager {
}