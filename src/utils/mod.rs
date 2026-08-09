use aes_gcm::Aes256Gcm;
use argon2::{
    Argon2,
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
    aead::{Aead, KeyInit},
    Key, Nonce,
};

use aes_gcm::aead::rand_core::RngCore;

use crate::data_struct::Secret;

const MAGIC: &[u8; 4] = b"VLT1"; // version/sanity tag, checked after decrypt


pub fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    // .expect() here is fine: encryption with a valid key/nonce only fails
    // on internal library misuse (e.g. plaintext too large), not bad input.
    cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure")
}

pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
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

pub struct VaultContents {
    pub secrets: Vec<Secret>,
}

impl VaultContents {
    /// Format: MAGIC || secret_count(u32 LE) || for each secret:
    ///   username_len(u32 LE) || username_bytes ||
    ///   password_len(u32 LE) || password_bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.secrets.len() as u32).to_le_bytes());

        for secret in &self.secrets {
            let i_bytes = secret.id.as_bytes();
            let u_bytes = secret.uname.as_bytes();
            let s_bytes = secret.secret.as_bytes();

            out.extend_from_slice(&(i_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(i_bytes);

            out.extend_from_slice(&(u_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(u_bytes);

            out.extend_from_slice(&(s_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(s_bytes);

            match &secret.hint {
                Some(h) => {
                    let h_bytes = h.as_bytes();
                    out.extend_from_slice(&(h_bytes.len() as u32).to_le_bytes());
                    out.extend_from_slice(h_bytes);
                },
                None => out.extend([0]),
            }
        }

        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ()> {
        if data.len() < 8 || &data[0..4] != MAGIC {
            return Err(()); // not our format / wrong password produced garbage
        }

        let mut pos = 4;
        let count = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| ())?);
        pos += 4;

        let mut secrets = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let u_len = read_u32(data, &mut pos)?;
            let username = read_string(data, &mut pos, u_len)?;

            let p_len = read_u32(data, &mut pos)?;
            let password = read_string(data, &mut pos, p_len)?;

            secrets.push(Vaultsecret { username, password });
        }

        Ok(VaultContents { secrets })
    }
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, ()> {
    let bytes = data.get(*pos..*pos + 4).ok_or(())?;
    *pos += 4;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| ())?))
}

fn read_string(data: &[u8], pos: &mut usize, len: u32) -> Result<String, ()> {
    let bytes = data.get(*pos..*pos + len as usize).ok_or(())?;
    *pos += len as usize;
    String::from_utf8(bytes.to_vec()).map_err(|_| ())
}