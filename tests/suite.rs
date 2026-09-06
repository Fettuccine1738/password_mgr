use pass_man::data_struct::NONCE_LEN;
use pass_man::data_struct::SALT_LEN;
use pass_man::data_struct::SALT_NONCE_LEN;
use pass_man::populate_vault;

// pub mod lib_test {

//     fn tests_lib_creation_is_succesful() {

//     }
// }

#[cfg(test)]
mod state_tests {
    use pass_man::data_struct::{
        LockedVault, UnlockedVault, VaultState, input::MockInput, vc::Secret,
    };

    #[test]
    fn limbo_remains_in_limbo() {
        let mut input = MockInput { lines: vec![] };

        let state = VaultState::Limbo;
        let next = state.transition(&mut input);

        assert!(matches!(next, VaultState::Limbo));
    }

    #[test]
    fn locked_vault_transitions_to_unlocked_with_correct_password() {
        let unlocked = UnlockedVault::for_new_vault("test-vault".to_owned(), "secret");
        let locked = unlocked.lock();
        let mut state = VaultState::Locked(locked);

        let mut input = MockInput {
            lines: vec!["secret".to_owned()],
        };

        state = state.transition(&mut input);

        match state {
            VaultState::Unlocked(vault) => {
                assert_eq!(vault.get_name(), "test-vault");
            }
            _ => panic!("expected unlocked vault"),
        }
    }

    #[test]
    fn locked_vault_remains_locked_with_wrong_password() {
        let unlocked = UnlockedVault::for_new_vault("test-vault".to_owned(), "secret");
        let locked = unlocked.lock();
        let mut state = VaultState::Locked(locked);

        let mut input = MockInput {
            lines: vec!["wrong-password".to_owned()],
        };

        state = state.transition(&mut input);

        assert!(matches!(state, VaultState::Locked(_)));
    }

    #[test]
    fn unlocked_vault_transitions_to_locked() {
        let unlocked = UnlockedVault::for_new_vault("test-vault".to_owned(), "secret");
        let mut state = VaultState::Unlocked(unlocked);
        let mut input = MockInput { lines: vec![] };

        state = state.transition(&mut input);

        assert!(matches!(state, VaultState::Locked(_)));
    }

    #[test]
    fn locked_and_unlocked_transitions_round_trip() {
        let unlocked = UnlockedVault::for_new_vault("test-vault".to_owned(), "secret");
        let mut state = VaultState::Unlocked(unlocked);
        let mut input = MockInput { lines: vec![] };

        state = state.transition(&mut input);
        assert!(matches!(state, VaultState::Locked(_)));

        let mut input = MockInput {
            lines: vec!["secret".to_owned()],
        };

        state = state.transition(&mut input);

        match state {
            VaultState::Unlocked(vault) => {
                assert_eq!(vault.get_name(), "test-vault");
            }
            _ => panic!("expected unlocked vault after round trip"),
        }
    }

    #[test]
    fn locked_vault_can_be_constructed_with_new_and_unlocked() {
        let locked = LockedVault::new("test-vault".to_owned());
        let unlocked = locked.unlock_new("secret");

        assert_eq!(unlocked.get_name(), "test-vault");
    }

    #[test]
    fn when_confirmed_then_update_existing_secret() {
        let initial = Secret::new(
            "id".to_owned(),
            "user".to_owned(),
            "old-secret".to_owned(),
            Some("example.com".to_owned()),
        );
        let replacement = Secret::new(
            "id".to_owned(),
            "user".to_owned(),
            "new-secret".to_owned(),
            Some("example.com".to_owned()),
        );
        let mut state = VaultState::Unlocked(UnlockedVault::for_new_vault(
            "test-vault".to_owned(),
            "secret",
        ));
        let mut input = MockInput { lines: vec![] };
        assert!(state.add_password(initial, &mut input));

        let mut input = MockInput {
            lines: vec!["yes".to_owned()],
        };
        let update_succeeded = state.add_password(replacement, &mut input);
        assert!(update_succeeded);

        match state {
            VaultState::Unlocked(vault) => {
                assert_eq!(vault.get_secrets_count(), 1);
                assert_eq!(
                    vault
                        .fetch_secret_for_website("example.com")
                        .unwrap()
                        .secret,
                    "new-secret"
                );
            }
            _ => panic!("expected unlocked vault"),
        }
    }

    #[test]
    fn declining_existing_secret_update_keeps_old_secret() {
        let initial = Secret::new(
            "id".to_owned(),
            "user".to_owned(),
            "old-secret".to_owned(),
            Some("example.com".to_owned()),
        );
        let replacement = Secret::new(
            "id".to_owned(),
            "user".to_owned(),
            "new-secret".to_owned(),
            Some("example.com".to_owned()),
        );
        let mut state = VaultState::Unlocked(UnlockedVault::for_new_vault(
            "test-vault".to_owned(),
            "secret",
        ));
        let mut input = MockInput { lines: vec![] };
        assert!(state.add_password(initial, &mut input));

        let mut input = MockInput {
            lines: vec!["no".to_owned()],
        };
        let update_succeeded = state.add_password(replacement, &mut input);
        assert!(!update_succeeded);

        match state {
            VaultState::Unlocked(vault) => {
                assert_eq!(vault.get_secrets_count(), 1);
                assert_eq!(
                    vault
                        .fetch_secret_for_website("example.com")
                        .unwrap()
                        .secret,
                    "old-secret"
                );
            }
            _ => panic!("expected unlocked vault"),
        }
    }
}

#[cfg(test)]
mod lock_unlock_tests {
    use pass_man::create_new_vault;
    use pass_man::data_struct::UnlockedVault;
    use pass_man::data_struct::input::MockInput;
    use tempfile::NamedTempFile;

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
    fn returns_none_when_shorter_than_salt_nonce_header() -> Result<(), Box<dyn std::error::Error>>
    {
        // SALT_NONCE_LEN - 1 bytes: not enough for salt+nonce, no ciphertext at all.
        let bytes = vec![0xAAu8; SALT_NONCE_LEN - 1];
        let mut file = NamedTempFile::new().expect("Error creating temporary test files");
        file.write_all(&bytes)?;
        let path = file.path().to_string_lossy();
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn returns_some_when_exactly_header_length_with_empty_ciphertext()
    -> Result<(), Box<dyn std::error::Error>> {
        // Exactly SALT_LEN + NONCE_LEN bytes: valid header, zero-length ciphertext.
        // The function only validates header length, not ciphertext content,
        // so this should still succeed at the populate_vault level.
        let bytes = vec![0xBBu8; SALT_NONCE_LEN];
        let mut file = NamedTempFile::new().expect("Error creating temporary test files");
        file.write_all(&bytes)?;
        let path = file.path().to_string_lossy();
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_some());
        Ok(())
    }

    #[test]
    fn correctly_splits_salt_nonce_and_preserves_name() -> Result<(), Box<dyn std::error::Error>> {
        let salt: [u8; SALT_LEN] = [1u8; SALT_LEN];
        let nonce: [u8; NONCE_LEN] = [2u8; NONCE_LEN];
        let ciphertext: [u8; 5] = [9, 9, 9, 9, 9];

        let mut bytes = Vec::with_capacity(SALT_NONCE_LEN + ciphertext.len());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);

        let mut file = NamedTempFile::new().expect("Error creating temporary test files");
        file.write_all(&bytes)?;
        let path = file.path().to_string_lossy();
        let result = populate_vault(&path, "myvault".to_owned());
        assert!(result.is_some());

        let lv = result.unwrap();
        assert_eq!(lv.get_salt(), &salt);
        assert_eq!(lv.get_nonce(), &nonce);

        Ok(())
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

    #[test]
    fn returns_some_when_password_confirmed_for_new_vault() {
        let mut input_src = MockInput {
            // name, password, confirm password
            lines: vec!["Dummy".to_owned(), "abc123".to_owned(), "abc123".to_owned()],
        };
        let uv = create_new_vault(&mut input_src);
        assert!(uv.is_some());
        let uv: UnlockedVault = uv.unwrap();
        assert!(uv.get_name() == "Dummy");
    }

    #[test]
    fn returns_none_when_password_not_confirmed_for_new_vault() {
        let mut input_src = MockInput {
            // name, password, 3x wrong passwords
            lines: vec![
                "Dummy".to_owned(),
                "abc123".to_owned(),
                "abc12".to_owned(),
                "abc12".to_owned(),
                "abc12".to_owned(),
            ],
        };
        dbg!(&input_src);
        let uv = create_new_vault(&mut input_src);
        assert!(uv.is_none());
    }
}

#[cfg(test)]
pub mod vc_test {
    use pass_man::data_struct::vc::Secret;
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
            cntnt: vec![secret1, secret2],
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

    #[test]
    fn test_validate_and_return_success() {
        let secret = Secret::validate_and_return(A.to_owned(), B.to_owned(), C.to_owned());
        assert!(secret.is_ok());
    }

    #[test]
    fn test_validate_and_return_failure() {
        let secret = Secret::validate_and_return(A.to_string(), "".to_string(), "".to_string());
        assert!(secret.is_err());
    }
}
