use argon2::{
    Argon2, password_hash::{
        self, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng
    }
};

pub fn hash_password(password: String) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let ph = PasswordHash::new(password_hash).unwrap();
    Argon2::default().verify_password(password.as_bytes(), &ph).is_ok()
}