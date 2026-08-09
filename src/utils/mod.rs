pub mod retry;

use aes_gcm::Aes256Gcm;
use argon2::{
    Argon2, Params as Argon2Params,
    password_hash::{
        self, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};

use std::io;

pub fn read_line(buffer: &mut String) {
    io::stdin().read_line(buffer).expect("Failed to read line");
}

pub fn hash_password(password: String) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let ph = PasswordHash::new(password_hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &ph)
        .is_ok()
}

use aes_gcm::{
    Key, Nonce,
    aead::{Aead, KeyInit},
};

pub const MAGIC: &[u8; 4] = b"VLT1"; // version/sanity tag, checked after decrypt

pub fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    // .expect() here is fine: encryption with a valid key/nonce only fails
    // on internal library misuse (e.g. plaintext too large), not bad input.
    cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure")
}

pub fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    // Err here means the AEAD tag didn't verify: wrong key (wrong password)
    // or tampered/corrupted ciphertext. We deliberately don't distinguish
    // the two — that distinction is not ours to leak.
    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}

pub fn generate_fresh_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    nonce
}

pub(crate) fn derive_key(pwd: &[u8], salt: &[u8], params: &Argon2Params) -> [u8; 32] {
    let mut output = [0u8; 32];
    Argon2::default()
        .hash_password_into(pwd, salt, &mut output)
        .expect(todo!("Key Derivation Fn should not fail here"));
    output
}
