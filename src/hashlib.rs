// dovecot-auth is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// dovecot-auth is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with dovecot-auth.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt::Display;

use base64::{engine::general_purpose, Engine as _};
use log::warn;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha512};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum Scheme {
    SHA512,
    SSHA512,
}

impl Scheme {
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::SHA512 => "{SHA512}",
            Self::SSHA512 => "{SSHA512}",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA512 => "SHA512",
            Self::SSHA512 => "SSHA512",
        }
    }
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SHA512 => write!(f, "SHA512"),
            Self::SSHA512 => write!(f, "SSHA512"),
        }
    }
}

impl TryFrom<&str> for Scheme {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value == Self::SHA512.as_str() || value.starts_with(Self::SHA512.prefix()) {
            Ok(Self::SHA512)
        } else if value == Self::SSHA512.as_str() || value.starts_with(Self::SSHA512.prefix()) {
            Ok(Self::SSHA512)
        } else {
            Err("unknown hash type")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Hash {
    pub scheme: Scheme,
    pub hash: String,
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = &self.scheme;
        let hash = &self.hash;
        write!(f, "{{{scheme}}}{hash}")
    }
}

impl TryFrom<&str> for Hash {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let scheme = Scheme::try_from(value)?;
        let start_pos = scheme.prefix().len();
        let hash = value[start_pos..].to_string();
        Ok(Self { scheme, hash })
    }
}

pub fn ssha512(password: &[u8], salt: &[u8]) -> Hash {
    let mut hasher = Sha512::new();
    hasher.update(password);
    hasher.update(salt);
    let hash_bytes = hasher.finalize();
    let salted_hash = [&hash_bytes, salt].concat();
    let hash = general_purpose::STANDARD.encode(salted_hash);
    Hash {
        scheme: Scheme::SSHA512,
        hash,
    }
}

pub fn sha512(password: &[u8]) -> Hash {
    let mut hasher = Sha512::new();
    hasher.update(password);
    let hash_bytes = hasher.finalize();
    let hash = general_purpose::STANDARD.encode(hash_bytes);
    Hash {
        scheme: Scheme::SHA512,
        hash,
    }
}

pub fn hash(password: &str, scheme: &Scheme) -> Hash {
    match scheme {
        Scheme::SSHA512 => {
            let salt: Vec<u8> = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(5)
                .collect();
            ssha512(password.as_bytes(), &salt)
        }
        Scheme::SHA512 => sha512(password.as_bytes()),
    }
}

pub fn verify_password(password: &str, hash: &Hash) -> bool {
    if password.is_empty() {
        return false;
    }

    let hash1 = match hash.scheme {
        Scheme::SSHA512 => {
            match general_purpose::STANDARD.decode(&hash.hash) {
                Ok(decoded_hash) => {
                    if decoded_hash.len() < 65 {
                        return false;
                    }
                    let salt = &decoded_hash[64..];
                    ssha512(password.as_bytes(), salt)
                }
                _ => {
                    warn!("base64: unable to decode hash: {hash}");
                    return false;
                }
            }
        }
        Scheme::SHA512 => sha512(password.as_bytes()),
    };

    hash == &hash1
}

pub fn find_hash<T: AsRef<str>>(password: T, hash_list: &[Hash]) -> Option<&Hash> {
    let password = password.as_ref();
    if password.is_empty() {
        return None;
    }

    if let Some(index) = hash_list
        .iter()
        .position(|hash| verify_password(password, hash))
    {
        return Some(&hash_list[index]);
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::hashlib::{find_hash, hash, verify_password, Scheme};

    const TEST_PASSWORD: &'static str = "TestPass ä?=%*@+-ç£{}()!#\"'~`";
    const TEST_PASSWORD2: &'static str = "TestPass2 ä?=%*@+-ç£{}()!#\"'~`";

    #[test]
    fn test_ssha512_hash_and_verify() {
        let test_hash = hash(&TEST_PASSWORD, &Scheme::SSHA512);
        assert_eq!(verify_password(TEST_PASSWORD, &test_hash), true);
    }

    #[test]
    fn test_sha512_hash_and_verify() {
        let test_hash = hash(&TEST_PASSWORD, &Scheme::SHA512);
        assert_eq!(verify_password(TEST_PASSWORD, &test_hash), true);
    }

    #[test]
    fn test_get_matching_hash() {
        let mut hashes = vec![
            hash("AnotherTestPassword", &Scheme::SSHA512),
            hash("AndAnotherTestPassword", &Scheme::SHA512),
        ];

        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), None);
        let ssha512_hash = hash(TEST_PASSWORD, &Scheme::SSHA512);
        hashes.insert(1, ssha512_hash.clone());
        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), Some(&ssha512_hash));

        assert_eq!(find_hash(TEST_PASSWORD2, &mut hashes), None);
        let sha512_hash = hash(TEST_PASSWORD2, &Scheme::SHA512);
        hashes.push(sha512_hash.clone());
        assert_eq!(find_hash(TEST_PASSWORD2, &mut hashes), Some(&sha512_hash));
    }
}
