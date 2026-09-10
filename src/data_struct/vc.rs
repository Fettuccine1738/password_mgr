use std::fmt::Display;

use crate::utils::DECRYPTION_CHECK_TAG;

///
///
/// TODO: Impl Hash for this, Secrets are owned by VaultContents which may be backed by a Map in the future
#[derive(Eq, Debug, Clone)]
pub struct Secret {
    pub id: String, // TODO: this is a unique id for the secret, for future use. 
    pub uname: Option<String>, // optional, but at least one of uname or website must be provided
    pub secret: String,
    pub website: Option<String>,
}

impl Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = writeln!(f, "Username: ");
        if let Some(s) = &self.uname {
            let _ = write!(f, "{}", s);
        } else {
            let _ = write!(f, "<NO Username set for this>");
        }
        let _ = writeln!(f, "secret = ");
        let _ = write!(f, "{}", self.secret);

        let _ = writeln!(f, "website = ");
        if let Some(s) = &self.website {
            write!(f, "{}", s)
        } else {
            write!(f, "<NO Passphrase set for this>")
        }
    }
}

impl Secret {
    pub fn new(id: String, name: String, secret: String, website: Option<String>) -> Self {
        Self {
            id,
            uname: Some(name),
            secret,
            website,
        }
    }

    // TODO: validate the secret, e.g. website is a valid URL, or empty
    pub fn validate_and_return(
        secret: String,
        uname: String,
        website: String,
    ) -> Result<Secret, String> {
        if secret.is_empty() {
            return Err("Secret's password cannot be empty".to_string());
        }

        if uname.is_empty() && website.is_empty() {
            return Err("Either username or website must be provided".to_string());
        }

        Ok(Secret {
            id: String::new(),
            uname: if uname.is_empty() { None } else { Some(uname) },
            secret,
            website: if website.is_empty() {
                None
            } else {
                Some(website)
            },
        })
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.uname == other.uname
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultContents {
    pub cntnt: Vec<Secret>,
}

impl VaultContents {
    /// Format: DECRYPTION_CHECK_TAG ||
    /// secret_count(u32 LE) || for each secret:
    ///   id_len(u32 LE) || id_bytes ||
    ///   username_len(u32 LE) || username_bytes ||
    ///   secret_len(u32 LE) || secret_bytes ||
    ///   Optional( == 0 means the hint does not exist) hint_len(u32 LE) || hint_bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DECRYPTION_CHECK_TAG);

        out.extend_from_slice(&(self.cntnt.len() as u32).to_le_bytes());

        for s in &self.cntnt {
            let i_bytes = s.id.as_bytes();
            out.extend_from_slice(&(i_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(i_bytes);

            match &s.uname {
                Some(u) => {
                    let u_bytes = u.as_bytes();
                    out.extend_from_slice(&(u_bytes.len() as u32).to_le_bytes());
                    out.extend_from_slice(u_bytes);
                }
                None => out.extend_from_slice(&(0u32).to_le_bytes()), // no id
            }

            let s_bytes = s.secret.as_bytes();
            out.extend_from_slice(&(s_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(s_bytes);

            match &s.website {
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
            let uname: Option<String> = if u_len == 0 {
                None
            } else {
                Some(read_string(data, &mut pos, u_len)?)
            };

            let s_len = read_u32(data, &mut pos)?;
            let secret = read_string(data, &mut pos, s_len)?;

            let h_len = read_u32(data, &mut pos)?;
            let website: Option<String> = if h_len == 0 {
                None
            } else {
                Some(read_string(data, &mut pos, h_len)?)
            };

            secrets.push(Secret {
                id,
                uname,
                secret,
                website,
            });
        }

        Ok(VaultContents { cntnt: secrets })
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
