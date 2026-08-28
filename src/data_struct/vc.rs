use super::Secret;
use crate::utils::DECRYPTION_CHECK_TAG;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultContents {
    pub secrets: Vec<Secret>,
}

impl VaultContents {
    // pub struct LockedVault {
    //     name: String,
    //     salt: [u8; 16],
    //     kdf_params: Argon2Params,
    //     nonce: [u8; 12],
    //     ciphertext: Vec<u8>, // includes AEAD tag
    // }

    /// Format: DECRYPTION_CHECK_TAG ||
    /// secret_count(u32 LE) || for each secret:
    ///   id_len(u32 LE) || id_bytes ||
    ///   username_len(u32 LE) || username_bytes ||
    ///   secret_len(u32 LE) || secret_bytes ||
    ///   Optional( == 0 means the hint does not exist) hint_len(u32 LE) || hint_bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DECRYPTION_CHECK_TAG);

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
                }
                None => out.extend_from_slice(&(0u32).to_le_bytes()), // no id == 0 exists so thats fine.
            }
        }
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ()> {
        if data.len() < 8 || &data[0..4] != DECRYPTION_CHECK_TAG {
            return Err(()); // not our format / wrong password produced garbage
        }

        let mut pos = 4;

        let count = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| ())?);
        pos += 4;

        let mut secrets = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let id_len = read_u32(data, &mut pos)?;
            let id = read_string(data, &mut pos, id_len)?;

            let u_len = read_u32(data, &mut pos)?;
            let uname = read_string(data, &mut pos, u_len)?;

            let s_len = read_u32(data, &mut pos)?;
            let secret = read_string(data, &mut pos, s_len)?;

            let h_len = read_u32(data, &mut pos)?;
            let hint: Option<String> = if h_len == 0 {
                None
            } else {
                Some(read_string(data, &mut pos, h_len)?)
            };

            secrets.push(Secret {
                id,
                uname,
                secret,
                hint,
            });
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
