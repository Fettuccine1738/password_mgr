use crate::data_struct::LockedVault;
use crate::data_struct::NONCE_LEN;
use crate::data_struct::SALT_LEN;
use crate::data_struct::SALT_NONCE_LEN;
use crate::data_struct::Secret;
use crate::data_struct::SignInError;
use crate::data_struct::UnlockError;
use crate::data_struct::UnlockedVault;
use crate::data_struct::VaultFiles;
use crate::data_struct::VaultState;
use crate::data_struct::input::InputSource;
use crate::utils::retry::BoolConditionRetry;
use crate::utils::retry::ErrCatchingRetry;
use crate::utils::retry::Retry;

use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::vec;

pub mod data_struct;
pub mod utils;

const STORE_DIR_PATH: &str = ".pass_mgr";
const INPUT_NAME_PROMPT: &str = "Enter Vault name: ";
const VAULT_READ_ME: &str = "Vault Storage
=============
This folder is used by pass_man to store encrypted vault files.

The contents of this folder should only be modified by pass_man itself,
through its normal lock/unlock operations.
Modifying this folder manually will corrupt vault files and make them
permanently undecryptable.";

fn validate_passwords(password: &str, confirm: &str) -> bool {
    let is_mtch = password == confirm;
    if !is_mtch {
        eprintln!("passwords do not match");
    }
    is_mtch
}

pub fn create_new_vault(src: &mut impl InputSource) -> Option<UnlockedVault> {
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
        return None;
    }

    Some(UnlockedVault::for_new_vault(name.to_owned(), &password))
}

fn write_locked_vault_to_file(filename: &str, lv: &LockedVault) -> io::Result<()> {
    let dir = get_store_dir_path();
    let final_path = dir.join(filename);
    let temp_path = dir.join(format!("{filename}.tmp"));

    let mut buf: Vec<u8> = vec![];
    buf.extend_from_slice(lv.get_salt());
    buf.extend_from_slice(lv.get_nonce());
    buf.extend_from_slice(lv.get_cipher()); // cipher already contains `DECRYPTION_TAG`

    {
        let mut tmp = File::create(&temp_path)?;
        tmp.write_all(&buf)?;
        tmp.sync_all()?
    } // tmp closed here 

    // filename either points to the old, fully-valid vault,
    // or the new, fully-valid vault. Avoiding mixed up data from crash windows
    // or  the process is killed mid-write
    fs::rename(&temp_path, &final_path)?;
    eprintln!("Vault saved as: {}", filename);
    Ok(())
}

pub fn sign_into_vault(
    vf: &VaultFiles,
    src: &mut impl InputSource,
) -> Result<UnlockedVault, SignInError> {
    eprintln!("---------Sign In----------");
    eprintln!("Enter a Vault name: ");
    let name = src.read_line(INPUT_NAME_PROMPT);
    let name = name.trim();

    let filepath = exists(name, vf);

    if filepath.is_empty() {
        return Err(SignInError::NotFound);
    }
    eprintln!("Vault with name `{}` found.", name);

    // exists succeeds but might fail due to TOCTOU errors with
    // the file.
    let lv: LockedVault = populate_vault(&filepath, name.to_owned()).unwrap();
    let mut err_retry: ErrCatchingRetry<UnlockedVault, (LockedVault, UnlockError)> =
        ErrCatchingRetry::default();

    match <ErrCatchingRetry<UnlockedVault, (LockedVault, UnlockError)> as Retry<
        Result<UnlockedVault, (LockedVault, UnlockError)>,
    >>::retry(&mut err_retry, || {
        let password = src.read_password("Enter password:\t");
        lv.clone().unlock(&password)
    }) {
        Ok(uv) => return Ok(uv),
        Err((lv, ue)) => Err(SignInError::Unlock(lv, ue)),
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

pub fn populate_vault(path: &str, vault_name: String) -> Option<LockedVault> {
    if let Ok(mut file) = File::open(path) {
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

        return Some(LockedVault::init(vault_name, salt, nonce, cipher));
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
pub fn add_password(_vs: &mut VaultState, _p: Secret) -> bool {
    false
}

pub fn get_secret(_id: String) -> Option<Secret> {
    None
}

pub fn get_secret_using(_hint: String) -> Option<Secret> {
    None
}

pub fn load_vault_files() -> Result<VaultFiles, std::io::Error> {
    let pbuf = &get_store_dir_path();
    if !std::fs::exists(pbuf).expect("Can't check existence of directory to be used as database") {
        match fs::create_dir(pbuf) {
            Ok(_) => {
                let mut read_me = fs::File::create_new(Path::new(pbuf).join("README.md"))?;
                read_me.write_all(VAULT_READ_ME.as_bytes())?;
                return Ok(VaultFiles::default());
            }
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

            if path.is_dir() {
                continue;
            }
            if path.file_name().and_then(|f| f.to_str()) == Some("README.md") {
                continue;
            }
            eprintln!("found {}", path.to_str().unwrap());
            v.push(path);
        }
    }

    Ok(VaultFiles(v))
}

fn get_store_dir_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME environment variable not set");
    std::path::Path::new(&home).join(STORE_DIR_PATH)
}
