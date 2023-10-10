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
use sha2::{Digest, Sha512, Sha256};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An implemented hash scheme
#[derive(Debug, Clone, PartialEq, Eq, EnumIter)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Scheme {
    SHA256,
    SSHA256,
    SHA512,
    SSHA512,
}

impl Scheme {
    /// Returns the scheme name, e.g. "SSHA512"
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA256 => "SHA256",
            Self::SSHA256 => "SSHA256",
            Self::SHA512 => "SHA512",
            Self::SSHA512 => "SSHA512",
        }
    }

    /// Returns the has prefix, e.g. "{SSHA512}"
    pub fn hash_prefix(&self) -> &'static str {
        match self {
            Self::SHA256 => "{SHA256}",
            Self::SSHA256 => "{SSHA256}",
            Self::SHA512 => "{SHA512}",
            Self::SSHA512 => "{SSHA512}",
        }
    }
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.as_str();
        write!(f, "{value}")
    }
}

impl TryFrom<&str> for Scheme {
    type Error = &'static str;

    /// Returns a scheme if the value is equal to a known scheme or starts with a known hash prefix
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds a prefixed hash or scheme name
    ///
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.to_uppercase();
        Self::iter()
            .find(|scheme| value.eq(scheme.as_str()) || value.starts_with(scheme.hash_prefix()))
            .ok_or("unknown hash scheme")
    }
}

/// A hash with a known scheme
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Hash {
    /// A hash must have a known scheme
    pub scheme: Scheme,
    /// The hash itself
    pub hash: String,
}

/// Returns the SHA256 hash of the value given
///
/// # Arguments
///
/// * `value` - A byte slice that holds the data to hash
///
pub fn sha256(value: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let hash = general_purpose::STANDARD.encode(hasher.finalize());
    Hash {
        scheme: Scheme::SHA256,
        hash,
    }
}

/// Returns the SSHA256 hash of the value and salt given
///
/// # Arguments
///
/// * `value` - A byte slice that holds the data to hash
/// * `salt` - A byte slice that holds the salt for the hash
///
pub fn ssha256(value: &[u8], salt: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.update(salt);
    let hash_bytes = hasher.finalize();
    let salted_hash = [&hash_bytes, salt].concat();
    let hash = general_purpose::STANDARD.encode(salted_hash);
    Hash {
        scheme: Scheme::SSHA256,
        hash,
    }
}

/// Returns the SHA512 hash of the value given
///
/// # Arguments
///
/// * `value` - A byte slice that holds the data to hash
///
pub fn sha512(value: &[u8]) -> Hash {
    let mut hasher = Sha512::new();
    hasher.update(value);
    let hash_bytes = hasher.finalize();
    let hash = general_purpose::STANDARD.encode(hash_bytes);
    Hash {
        scheme: Scheme::SHA512,
        hash,
    }
}

/// Returns the SSHA512 hash of the value and salt given
///
/// # Arguments
///
/// * `value` - A byte slice that holds the data to hash
/// * `salt` - A byte slice that holds the salt for the hash
///
pub fn ssha512(value: &[u8], salt: &[u8]) -> Hash {
    let mut hasher = Sha512::new();
    hasher.update(value);
    hasher.update(salt);
    let hash_bytes = hasher.finalize();
    let salted_hash = [&hash_bytes, salt].concat();
    let hash = general_purpose::STANDARD.encode(salted_hash);
    Hash {
        scheme: Scheme::SSHA512,
        hash,
    }
}

impl Hash {
    /// Returns a hash of the value and scheme given
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds the data to hash
    /// * `scheme` - The hash scheme to use
    ///
    pub fn new<T: AsRef<str>>(value: T, scheme: &Scheme) -> Self {
        let value = value.as_ref().as_bytes();
        match scheme {
            Scheme::SHA256 => sha256(value),
            Scheme::SSHA256 => {
                let salt: Vec<u8> = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(5)
                    .collect();
                ssha256(value, &salt)
            }
            Scheme::SHA512 => sha512(value),
            Scheme::SSHA512 => {
                let salt: Vec<u8> = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(5)
                    .collect();
                ssha512(value, &salt)
            }
        }
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = self.scheme.hash_prefix();
        let hash = &self.hash;
        write!(f, "{scheme}{hash}")
    }
}

impl TryFrom<&str> for Hash {
    type Error = &'static str;

    /// Returns a hash if the value is equal to a known scheme or starts with a known hash prefix
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds a prefixed hash
    ///
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let scheme = Scheme::try_from(value)?;
        let start_pos = scheme.hash_prefix().len();
        let hash = value[start_pos..].to_string();
        if hash.is_empty() {
            return Err("empty hash");
        }
        Ok(Self { scheme, hash })
    }
}

/// Returns true if the given value matches to the given hash
///
/// # Arguments
///
/// * `value` - A string slice that holds the value to verify
/// * `hash` - A hash by which the value is verified
///
pub fn verify_value<T: AsRef<str>>(value: T, hash: &Hash) -> bool {
    let value = value.as_ref();
    if value.is_empty() {
        return false;
    }

    let hash1 = match hash.scheme {
        Scheme::SHA256 => sha256(value.as_bytes()),
        Scheme::SSHA256 => match general_purpose::STANDARD.decode(&hash.hash) {
            Ok(decoded_hash) => {
                if decoded_hash.len() < 65 {
                    return false;
                }
                let salt = &decoded_hash[64..];
                ssha256(value.as_bytes(), salt)
            }
            _ => {
                warn!("base64: unable to decode hash: {hash}");
                return false;
            }
        },
        Scheme::SHA512 => sha512(value.as_bytes()),
        Scheme::SSHA512 => match general_purpose::STANDARD.decode(&hash.hash) {
            Ok(decoded_hash) => {
                if decoded_hash.len() < 65 {
                    return false;
                }
                let salt = &decoded_hash[64..];
                ssha512(value.as_bytes(), salt)
            }
            _ => {
                warn!("base64: unable to decode hash: {hash}");
                return false;
            }
        },
    };

    hash == &hash1
}

/// Verifies the value to every hash in the list and returns an optional reference to the first matching hash
///
/// # Arguments
///
/// * `value` - A string slice that holds the value to verify
/// * `hash_list` - A list of hashes to verify the value with
///
pub fn find_hash<T: AsRef<str>>(value: T, hash_list: &[Hash]) -> Option<&Hash> {
    let value = value.as_ref();
    if value.is_empty() {
        return None;
    }

    if let Some(index) = hash_list.iter().position(|hash| verify_value(value, hash)) {
        return Some(&hash_list[index]);
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::hashlib::{find_hash, verify_value, Hash, Scheme};

    const TEST_PASSWORD: &'static str = "TestPass ä?=%*@+-ç£{}()!#\"'~`";
    const TEST_PASSWORD2: &'static str = "TestPass2 ä?=%*@+-ç£{}()!#\"'~`";

    const TEST_PASSWORD_SSHA512: &'static str = "{SSHA512}gcZ28b5vc9Vbj4yWcKWh8uAPKrGsaa5nHSbuS4q2kxvIIKfTVBDMC/3oZOFPa4gTEMODWdydoimakyp4r01V128xTWh3";
    const TEST_PASSWORD_SSHA512_BAD: &'static str = "{SSHA512}gcZ28b5vc9Vbj4yWcKWh8uAPKrGsaa5nHSbuS4q2kxvIIKfTVBDMC/3oZOFPa4gTEMODWdydoimakyp4r01V128xTWh4";
    const TEST_PASSWORD_SHA512: &'static str = "{SHA512}ZzYTXW02PU1y/z4tXXBmoXSJihXhpnaTODYof7GpLfjkFycWLBKLdHkP4bRWEkYJsD3HjgTn2drxj8nzgBUckQ==";
    const TEST_PASSWORD_SHA512_BAD: &'static str = "{SHA512}ZzYTXW02PU1y/z4tXXBmoXSJihXhpnaTODYof7GpLfjkFycWLBKLdHkP4bRWEkYJsD3HjgTn2drxj8nzgAUckQ==";

    #[test]
    fn test_ssha512_hash_and_verify() {
        let test_hash = Hash::new(&TEST_PASSWORD, &Scheme::SSHA512);
        assert_eq!(verify_value(TEST_PASSWORD, &test_hash), true);
    }

    #[test]
    fn test_sha512_hash_and_verify() {
        let test_hash = Hash::new(&TEST_PASSWORD, &Scheme::SHA512);
        assert_eq!(verify_value(TEST_PASSWORD, &test_hash), true);
    }

    #[test]
    fn test_get_matching_hash() {
        let mut hashes = vec![
            Hash::new("AnotherTestPassword", &Scheme::SSHA512),
            Hash::new("AndAnotherTestPassword", &Scheme::SHA512),
        ];

        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), None);
        let ssha512_hash = Hash::new(TEST_PASSWORD, &Scheme::SSHA512);
        hashes.insert(1, ssha512_hash.clone());
        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), Some(&ssha512_hash));

        assert_eq!(find_hash(TEST_PASSWORD2, &mut hashes), None);
        let sha512_hash = Hash::new(TEST_PASSWORD2, &Scheme::SHA512);
        hashes.push(sha512_hash.clone());
        assert_eq!(find_hash(TEST_PASSWORD2, &mut hashes), Some(&sha512_hash));
    }

    #[test]
    fn test_display_and_tryfrom() {
        let ssha512_hash = Hash::new(TEST_PASSWORD, &Scheme::SSHA512);
        let hash_string = ssha512_hash.to_string();
        assert_eq!(Hash::try_from(hash_string.as_str()), Ok(ssha512_hash));

        let sha512_hash = Hash::new(TEST_PASSWORD, &Scheme::SHA512);
        let hash_string = sha512_hash.to_string();
        assert_eq!(Hash::try_from(hash_string.as_str()), Ok(sha512_hash));

        assert_eq!(
            Hash::try_from("{INVALID}HASHDATA"),
            Err("unknown hash scheme")
        );
        assert_eq!(Hash::try_from("{SHA512}"), Err("empty hash"));
    }

    #[test]
    fn test_verify_password() {
        let ssha512_hash = Hash::try_from(TEST_PASSWORD_SSHA512).unwrap();
        let ssha512_hash_bad = Hash::try_from(TEST_PASSWORD_SSHA512_BAD).unwrap();
        assert_eq!(verify_value(TEST_PASSWORD, &ssha512_hash), true);
        assert_eq!(verify_value(TEST_PASSWORD, &ssha512_hash_bad), false);

        let sha512_hash = Hash::try_from(TEST_PASSWORD_SHA512).unwrap();
        let sha512_hash_bad = Hash::try_from(TEST_PASSWORD_SHA512_BAD).unwrap();
        assert_eq!(verify_value(TEST_PASSWORD, &sha512_hash), true);
        assert_eq!(verify_value(TEST_PASSWORD, &sha512_hash_bad), false);
    }
}
