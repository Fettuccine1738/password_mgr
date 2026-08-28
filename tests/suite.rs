use pass_man::data_struct::SALT_LEN;
use pass_man::data_struct::NONCE_LEN;
use pass_man::data_struct::SALT_NONCE_LEN;
use pass_man::populate_vault;

// pub mod lib_test {

//     fn tests_lib_creation_is_succesful() {

//     }
// }

#[cfg(test)]
mod vault_test {
    use tempfile::{NamedTempFile, tempfile};

use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Writes `bytes` to a fresh temp file and returns its path as a String.
    /// Uses a process-id + counter suffix so parallel test runs never collide.
    fn write_temp_file(bytes: &[u8]) -> String {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path: PathBuf = std::env::temp_dir();
        path.push(format!("populate_vault_test_{}_{}", std::process::id(), n));
        let mut file = File::create(&path).expect("failed to create temp file");
        file.write_all(bytes).expect("failed to write temp file");
        path.to_string_lossy().into_owned()
    }

    fn nonexistent_path() -> String {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path: PathBuf = std::env::temp_dir();
        path.push(format!(
            "populate_vault_test_missing_{}_{}",
            std::process::id(),
            n
        ));
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn returns_none_when_file_does_not_exist() {
        let path = nonexistent_path();
        let result = pass_man::populate_vault(&path, "myvault".to_owned());
        assert!(result.is_none());
    }

    #[test]
    fn returns_none_for_empty_file() {
        let file = NamedTempFile::new().expect("Error creating temporary test files");
        let path = file.path().to_string_lossy();
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_none());
    }

    #[test]
    fn returns_none_when_shorter_than_salt_nonce_header() {
        // SALT_NONCE_LEN - 1 bytes: not enough for salt+nonce, no ciphertext at all.
        let bytes = vec![0xAAu8; SALT_NONCE_LEN - 1];
        let path = write_temp_file(&bytes);
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn returns_some_when_exactly_header_length_with_empty_ciphertext() {
        // Exactly SALT_LEN + NONCE_LEN bytes: valid header, zero-length ciphertext.
        // The function only validates header length, not ciphertext content,
        // so this should still succeed at the populate_vault level.
        let bytes = vec![0xBBu8; SALT_NONCE_LEN];
        let path = write_temp_file(&bytes);
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn correctly_splits_salt_nonce_and_preserves_name() {
        let salt: [u8; SALT_LEN] = [1u8; SALT_LEN];
        let nonce: [u8; NONCE_LEN] = [2u8; NONCE_LEN];
        let ciphertext: [u8; 5] = [9, 9, 9, 9, 9];

        let mut bytes = Vec::with_capacity(SALT_NONCE_LEN + ciphertext.len());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);

        let path = write_temp_file(&bytes);
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_some());

        let lv = result.unwrap();
        assert_eq!(lv.get_salt(), &salt);
        assert_eq!(lv.get_nonce(), &nonce);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn well_formed_file_with_realistic_ciphertext_length() {
        // Simulate a plausible on-disk vault: header + a longer ciphertext blob.
        let salt: [u8; SALT_LEN] = [7u8; SALT_LEN];
        let nonce: [u8; NONCE_LEN] = [3u8; NONCE_LEN];
        let ciphertext = vec![0x42u8; 128]; // arbitrary "encrypted" payload + tag

        let mut bytes = Vec::with_capacity(SALT_NONCE_LEN + ciphertext.len());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);

        let path = write_temp_file(&bytes);
        let result = populate_vault(&path, "another-vault".to_owned());
        assert!(result.is_some());

        let lv = result.unwrap();
        assert_eq!(lv.get_salt(), &salt);
        assert_eq!(lv.get_nonce(), &nonce);

        let _ = std::fs::remove_file(&path);
    }
}
#[cfg(test)]
pub mod vc_test {
    use pass_man::data_struct::Secret;
    use pass_man::data_struct::vc::VaultContents;
    use pass_man::utils::DECRYPTION_CHECK_TAG;

    const A: &str = "https://claude.ai/";
    const B: &str = "Mike";
    const C: &str = "pass1";

    const D: &str = "https://gmail.ai/";
    const E: &str = "Mike@gmail.com";
    const F: &str = "passw";
    const G: &str = "my student mail";

    fn helper_get_serialized_secrets() -> VaultContents {
        let secret1: Secret = Secret::new(A.to_owned(), B.to_owned(), C.to_owned(), None);
        let secret2: Secret =
            Secret::new(D.to_owned(), E.to_owned(), F.to_owned(), Some(G.to_owned()));

        let vc: VaultContents = VaultContents {
            secrets: vec![secret1, secret2],
        };

        vc
    }

    #[test]
    fn test_serialize_success() {
        let expected_len = DECRYPTION_CHECK_TAG.len()
            + A.bytes().len()
            + B.bytes().len()
            + C.bytes().len()
            + D.bytes().len()
            + E.bytes().len()
            + F.bytes().len()
            + G.bytes().len();
        let ctnt: Vec<u8> = helper_get_serialized_secrets().serialize();
        assert!(ctnt.len() > expected_len); // ctnt adds the length of valid fields before serializing the field's value 
    }

    #[test]
    fn test_deser_success_on_well_formed() {
        let vc = helper_get_serialized_secrets();
        let ctnt = vc.serialize();
        let ds = VaultContents::deserialize(&ctnt);
        assert!(ds.is_ok());
        assert_eq!(vc, ds.unwrap());
    }

    #[test]
    fn test_deser_fails_on_malformed_data() {
        let ctnt: Vec<u8> = vec![1, 2, 3, 4];
        let ds = VaultContents::deserialize(&ctnt);
        assert!(ds.is_err());
    }
}
