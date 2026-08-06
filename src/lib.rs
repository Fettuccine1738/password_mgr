use crate::data_struct::LockedVault;
use crate::data_struct::Password;
use crate::data_struct::UnlockedVault;
pub mod data_struct;
pub mod utils;

pub fn create_new_vault() -> UnlockedVault {
    todo!()
}

pub fn sign_into_vault() -> Result<UnlockedVault, std::io::Error> {
    let name = todo!();
    let v = get_vault_with(name);
    let password = todo!();
    let maybe_unlocked = v.unwrap().unlock(password);
}

pub fn get_vault_with(name: &str) -> Option<LockedVault> {
    None
}

/// adds a password to a `Vault`. 
/// 
/// # Arguments
/// * `uv` - UnlockedVault to store password to.
/// * `p` - Password details to be stored.
/// 
/// # Returns
/// true - if no instance of this password existed before storage
/// false - if a password with the same username and id exists
pub fn add_password(uv: UnlockedVault, p: Password) -> bool {
    false
}

pub fn get_password() -> Option<Password> {
    None
}
