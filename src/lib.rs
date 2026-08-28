use crate::data_struct::LockedVault;
use crate::data_struct::NONCE_LEN;
use crate::data_struct::SALT_LEN;
use crate::data_struct::SALT_NONCE_LEN;
use crate::data_struct::Secret;
use crate::data_struct::UnlockError;
use crate::data_struct::UnlockedVault;
use crate::data_struct::VaultFiles;
use crate::data_struct::input::InputSource;
use crate::utils::DECRYPTION_CHECK_TAG;
use crate::utils::retry::BoolConditionRetry;
use crate::utils::retry::ErrCatchingRetry;
use crate::utils::retry::Retry;

use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::vec;

pub mod data_struct;
pub mod utils;

const STORE_DIR_PATH: &str = ".pass_mgr";
const INPUT_NAME_PROMPT: &str = "Enter Vault name: ";
const EXIT_CODE_WRONG_PASSWORD: i32 = 67;

fn validate_passwords(password: &str, confirm: &str) -> bool {
    let is_mtch = password == confirm;
    if !is_mtch {
        eprintln!("passwords do not match");
    }
    is_mtch
}

pub fn create_new_vault(src: &mut impl InputSource) -> UnlockedVault {
    eprintln!("Creating a new vault...");
    eprintln!("Please provide a name for the vault. NOTE: This can never be changed again:");

    let name = src.read_line(INPUT_NAME_PROMPT);
    let name = name.trim();

    eprintln!("Please enter a master password. NOTE: You can change this anytime:");
    let password: String = src.read_password("Please enter password:\t");

    let mut m = BoolConditionRetry::default();

    if !(<BoolConditionRetry as Retry<bool>>::retry(&mut m, || {
        let confirm: String = src.read_password("Confirm password:\t");
        validate_passwords(&password, &confirm)
    })) {
        println!("Max tries = {} exceeded", m.get_tries_max());
        std::process::exit(EXIT_CODE_WRONG_PASSWORD);
    }

    UnlockedVault::for_new_vault(name.to_owned(), &password)
}

/// Only a locked vault can be saved and written to storage 
fn save_locked_vault_as_file(filename: &str, lv: &LockedVault) {
    let path = get_store_dir_path().join(filename);
    match std::fs::File::create(path) {
        Ok(mut file) => {
            eprintln!("New Vault create and saved as: {}.cvv", filename);
            let mut buf: Vec<u8> = vec![];
            buf.extend_from_slice(lv.get_salt());
            buf.extend_from_slice(lv.get_nonce());
            buf.extend_from_slice(DECRYPTION_CHECK_TAG);
            let _ = file.write_all(&buf); // TODO: fix  possible errors.
        }
        Err(_) => eprintln!("{}.cvv could not be creaed", filename),
    }
}

pub fn sign_into_vault(
    vf: &VaultFiles,
    src: &mut impl InputSource,
) -> Result<UnlockedVault, (LockedVault, UnlockError)> {
    eprintln!("---------Sign In----------");
    eprintln!("Enter a Vault name: ");
    let name = src.read_line(INPUT_NAME_PROMPT);
    let name = name.trim();

    let filepath = exists(name, vf);

    if filepath.is_empty() {
        return Err(UnlockError::Io(io::Error));
    } 
        eprintln!("Vault with name `{}` found.", name);

        // exists succeeds but might fail due to TOCTOU errors with
        // the file.
        let lv: LockedVault = populate_vault(name, filepath).unwrap();
        let mut err_retry: ErrCatchingRetry<UnlockedVault, (LockedVault, UnlockError)> =
            ErrCatchingRetry::default();

        match <ErrCatchingRetry<UnlockedVault, (LockedVault, UnlockError)> as Retry<
            Result<UnlockedVault, (LockedVault, UnlockError)>,
        >>::retry(&mut err_retry, || {
            let password = src.read_password("Enter password:\t");
            lv.clone().unlock(&password)
        }) {
            Ok(uv) => return Ok(uv),
            Err((lv, ue)) => todo!(),
        }
}

pub fn exists(name: &str, vf: &VaultFiles) -> String {
    let base = get_store_dir_path();

    for path in &vf.0 {
        let token = path.strip_prefix(&base).expect(
            &(format!(
                "Error stripping base = `{}` from path = `{}`",
                base.to_str().unwrap(),
                path.to_str().unwrap()
            )),
        );

        if token.to_str().unwrap() == name {
            return path.to_str().unwrap().to_string();
        }
    }

    String::new()
}

fn populate_vault(path: &str, name: String) -> Option<LockedVault> {
    if let Ok(mut file) = File::open(path) {
        // let bytes = file.bytes();
        // let data = bytes.flat_map(|b| b.ok()).collect::<Vec<u8>>();
        let mut buf = vec![];
        match file.read_to_end(&mut buf) {
            Ok(_) => (),
            Err(_) => return None,
        };

        // we know the unencrypted header is the sum of nonce and salt
        if buf.len() < SALT_NONCE_LEN {
            return None;
        }

        let (salt_nonce, cipher) = buf.split_at(SALT_NONCE_LEN);
        let (s, n) = salt_nonce.split_at(SALT_LEN);
        let mut salt: [u8; SALT_LEN] = [0u8; SALT_LEN];
        let mut nonce: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

        salt.copy_from_slice(&s);
        nonce.copy_from_slice(&n);

        return Some(LockedVault::init(name, salt, nonce, cipher));
    }

    None
}

/// adds a password to a `Vault`.
///
/// # Arguments
/// * `uv` - UnlockedVault to store password to.
/// * `p` - Secret details to be stored.
///
/// # Returns
/// true - if no instance of this password existed before storage
/// false - if a password with the same username and id exists
pub fn add_password(uv: UnlockedVault, p: Secret) -> bool {
    false
}

pub fn get_secret(id: String) -> Option<Secret> {
    None
}

pub fn get_secret_using(hint: String) -> Option<Secret> {
    None
}

pub fn load_vault_files() -> Result<VaultFiles, std::io::Error> {
    let pbuf = &get_store_dir_path();
    if !std::fs::exists(pbuf).expect("Can't check existence of file does_not_exist.txt") {
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
