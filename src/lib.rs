use crate::data_struct::LockedVault;
use crate::data_struct::Password;
use crate::data_struct::UnlockedVault;
use crate::data_struct::VaultFiles;

use std::fs;
use std::path::PathBuf;

pub mod data_struct;
pub mod utils;

const STORE_DIR_PATH: &str = ".pass_mgr";

pub fn create_new_vault() -> UnlockedVault {
    eprintln!("Creating a new vault...");
    eprintln!("Please provide a name for the vault. NOTE: This can never be changed again:");
    let mut name = String::new();
    utils::read_line(&mut name);
    let name = name.trim();

    eprintln!("Please enter a master password. NOTE: You can change this anytime:");
    let mut password = String::new();
    utils::read_line(&mut password);
    let password = password.trim();

    let filename = name.to_owned() + ".cvv";
    save_file_under_dir(&filename);
    UnlockedVault::init_no_store(name.to_owned(), password.to_owned())
}

fn save_file_under_dir(filename: &str) {
    let path = get_store_dir_path().join(filename);
    match std::fs::File::create(path) {
        Ok(_) => eprintln!("New Vault create and saved as: {}.cvv", filename),
        Err(_) => eprintln!("{}.cvv could not be creaed", filename),
    }
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

pub fn load_vault_files() -> Result<VaultFiles, std::io::Error> {
    let pbuf = &get_store_dir_path();
    if !std::fs::exists(pbuf)
        .expect("Can't check existence of file does_not_exist.txt")
    {
        match fs::create_dir(pbuf) {
            Ok(_) => return Ok(VaultFiles::default()),
            Err(_) => eprintln!("Could not create directory path"),
        }
    }
    eprintln!("Loading Vaults...");

    let mut v = vec![];

    if pbuf.is_dir() {
        for entry in fs::read_dir(pbuf)? {
            let entry = entry?;
            let path = entry.path();
            eprintln!("found {}", path.to_str().unwrap());

            if !path.is_dir() {
                v.push(entry.path().clone());
            }
        }
    }

    Ok(VaultFiles(v))
}

fn get_store_dir_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME environment variable not set");
    std::path::Path::new(&home).join(STORE_DIR_PATH)
}
