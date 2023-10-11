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

//! The hashlib implements hash functions compatible to Dovecot.

use std::fmt::Display;

use base64::{engine::general_purpose, Engine as _};
use hex;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const SSHA256_SALT_LEN: usize = 4;
const SSHA512_SALT_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// Represents a hash encoding
pub enum Encoding {
    Base64,
    B64,
    Hex,
    None,
}

impl Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64 => write!(f, "base64"),
            Self::B64 => write!(f, "b64"),
            Self::Hex => write!(f, "hex"),
            Self::None => write!(f, ""),
        }
    }
}

impl TryFrom<&str> for Encoding {
    type Error = String;

    /// Returns an encoding if the value equals to "base64" or "hex".
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds the name of the encoding
    ///
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "base64" => Ok(Self::Base64),
            "b64" => Ok(Self::B64),
            "hex" => Ok(Self::Hex),
            _ => Err(format!("unknown encoding: {value}")),
        }
    }
}

impl Encoding {
    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            Self::Base64 | Self::B64 => general_purpose::STANDARD.encode(data),
            Self::Hex => hex::encode(data),
            Self::None => String::from_utf8_lossy(data).to_string(),
        }
    }

    pub fn decode<T: AsRef<[u8]>>(&self, data: T) -> Result<Vec<u8>, String> {
        match self {
            Self::Base64 | Self::B64 => general_purpose::STANDARD
                .decode(data)
                .map_err(|err| err.to_string()),
            Self::Hex => hex::decode(data).map_err(|err| err.to_string()),
            Self::None => Ok(data.as_ref().to_vec()),
        }
    }
}

/// Represents a hash scheme
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Scheme {
    SHA256,
    SSHA256,
    SHA512,
    SSHA512,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SHA256 => write!(f, "SHA256"),
            Self::SSHA256 => write!(f, "SSHA256"),
            Self::SHA512 => write!(f, "SHA512"),
            Self::SSHA512 => write!(f, "SSHA512"),
        }
    }
}

impl TryFrom<&str> for Scheme {
    type Error = String;

    /// Returns a scheme if the value equals a known hash scheme.
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds the name of the hash scheme
    ///
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "SHA256" => Ok(Self::SHA256),
            "SSHA256" => Ok(Self::SSHA256),
            "SHA512" => Ok(Self::SHA512),
            "SSHA512" => Ok(Self::SSHA512),
            _ => Err(format!("unknown scheme: {value}")),
        }
    }
}

impl Scheme {
    /// Returns the default encoding of the scheme
    pub fn default_encoding(&self) -> Encoding {
        match self {
            Self::SHA256 => Encoding::Base64,
            Self::SSHA256 => Encoding::Base64,
            Self::SHA512 => Encoding::Base64,
            Self::SSHA512 => Encoding::Base64,
        }
    }
}

/// A hash with a known scheme
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Hash {
    pub encoding: Option<Encoding>,
    pub scheme: Scheme,
    hash: Vec<u8>,
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.encoding.as_ref() {
            Some(encoding) => format!("{{{}.{encoding}}}", self.scheme),
            None => format!("{{{}}}", self.scheme),
        };
        let hash = self
            .encoding
            .as_ref()
            .unwrap_or(&self.scheme.default_encoding())
            .encode(&self.hash);
        write!(f, "{prefix}{hash}")
    }
}

impl TryFrom<&str> for Hash {
    type Error = String;

    /// Returns a hash if the value is equal to a known scheme or starts with a known hash prefix
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds a prefixed hash
    ///
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.starts_with('{') {
            return Err("hash is not prefixed".to_string());
        }
        let prefix_end = value.find('}').ok_or("invalid hash prefix")?;
        let prefix = &value[1..prefix_end];

        let encoded_hash = &value[prefix_end + 1..];
        if encoded_hash.is_empty() {
            return Err("empty hash".to_string());
        }

        let (scheme, encoding) = match prefix.find('.') {
            Some(p) => {
                let scheme = Scheme::try_from(&prefix[0..p])?;
                let encoding = Encoding::try_from(&prefix[p + 1..])?;
                (scheme, Some(encoding))
            }
            None => (Scheme::try_from(prefix)?, None),
        };

        let hash = match &encoding {
            Some(encoding) => encoding.decode(encoded_hash)?,
            None => match scheme.default_encoding() {
                Encoding::Hex => Encoding::Hex
                    .decode(encoded_hash)
                    .unwrap_or(Encoding::Base64.decode(encoded_hash)?),
                _ => Encoding::Base64.decode(encoded_hash)?,
            },
        };

        Ok(Self {
            encoding,
            scheme,
            hash,
        })
    }
}

impl Hash {
    /// Returns a hash of the value and scheme given
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds the data to hash
    /// * `scheme` - The hash scheme to use
    /// * `encoding` - Optional encoding to use, defaults to base64
    ///
    pub fn new<T: AsRef<str>>(value: T, scheme: Scheme) -> Self {
        let value = value.as_ref().as_bytes();
        match scheme {
            Scheme::SHA256 => Self::sha256(value, None),
            Scheme::SSHA256 => Self::ssha256(value, None, None),
            Scheme::SHA512 => Self::sha512(value, None),
            Scheme::SSHA512 => Self::ssha512(value, None, None),
        }
    }

    /// Returns a randomly generated salt with the size given
    pub fn generate_salt(size: usize) -> Vec<u8> {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(size)
            .collect()
    }

    /// Returns the SHA256 hash of the value given
    ///
    /// # Arguments
    ///
    /// * `value` - A byte slice that holds the data to hash
    ///
    pub fn sha256(value: &[u8], encoding: Option<Encoding>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value);
        Hash {
            encoding,
            scheme: Scheme::SHA256,
            hash: hasher.finalize().to_vec(),
        }
    }

    /// Returns the SSHA256 hash of the value and salt given
    ///
    /// # Arguments
    ///
    /// * `value` - A byte slice that holds the data to hash
    /// * `salt` - An optional byte slice that holds the salt for the hash
    ///
    pub fn ssha256(value: &[u8], salt: Option<&[u8]>, encoding: Option<Encoding>) -> Hash {
        let salt = salt
            .map(|s| s.to_vec())
            .unwrap_or(Self::generate_salt(SSHA256_SALT_LEN));
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.update(&salt);
        let hash = hasher.finalize().to_vec();
        Hash {
            encoding,
            scheme: Scheme::SSHA256,
            hash: [hash, salt].concat(),
        }
    }

    /// Returns the SHA512 hash of the value given
    ///
    /// # Arguments
    ///
    /// * `value` - A byte slice that holds the data to hash
    ///
    pub fn sha512(value: &[u8], encoding: Option<Encoding>) -> Hash {
        let mut hasher = Sha512::new();
        hasher.update(value);
        Hash {
            encoding,
            scheme: Scheme::SHA512,
            hash: hasher.finalize().to_vec(),
        }
    }

    /// Returns the SSHA512 hash of the value and salt given
    ///
    /// # Arguments
    ///
    /// * `value` - A byte slice that holds the data to hash
    /// * `salt` - An optional byte slice that holds the salt for the hash
    ///
    pub fn ssha512(value: &[u8], salt: Option<&[u8]>, encoding: Option<Encoding>) -> Hash {
        let salt = salt
            .map(|s| s.to_vec())
            .unwrap_or(Self::generate_salt(SSHA512_SALT_LEN));
        let mut hasher = Sha512::new();
        hasher.update(value);
        hasher.update(&salt);
        let hash = hasher.finalize().to_vec();
        Hash {
            encoding,
            scheme: Scheme::SSHA512,
            hash: [hash, salt].concat(),
        }
    }

    /// Returns true if the given value matches to the given hash
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice that holds the value to verify
    ///
    pub fn verify<T: AsRef<str>>(&self, value: T) -> bool {
        let value = value.as_ref().as_bytes();
        if value.is_empty() {
            return false;
        }

        let hash = match self.scheme {
            Scheme::SHA256 => Self::sha256(value, None),
            Scheme::SSHA256 => {
                if self.hash.len() < 33 {
                    return false;
                }
                let salt = Some(&self.hash[32..]);
                Self::ssha256(value, salt, None)
            }
            Scheme::SHA512 => Self::sha512(value, None),
            Scheme::SSHA512 => {
                if self.hash.len() < 65 {
                    return false;
                }
                let salt = Some(&self.hash[64..]);
                Self::ssha512(value, salt, None)
            }
        };

        self.hash == hash.hash
    }
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

    if let Some(index) = hash_list.iter().position(|hash| hash.verify(value)) {
        return Some(&hash_list[index]);
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::hashlib::{find_hash, Hash, Scheme};

    const TEST_PASSWORD: &'static str = "TestPass ä?=%*@+-ç£{}()!#\"'~`";
    const TEST_PASSWORD2: &'static str = "TestPass2 ä?=%*@+-ç£{}()!#\"'~`";

    const TEST_PASSWORD_SSHA512: &'static str = "{SSHA512}gcZ28b5vc9Vbj4yWcKWh8uAPKrGsaa5nHSbuS4q2kxvIIKfTVBDMC/3oZOFPa4gTEMODWdydoimakyp4r01V128xTWh3";
    const TEST_PASSWORD_SSHA512_BAD: &'static str = "{SSHA512}gcZ28b5vc9Vbj4yWcKWh8uAPKrGsaa5nHSbuS4q2kxvIIKfTVBDMC/3oZOFPa4gTEMODWdydoimakyp4r01V128xTWh4";
    const TEST_PASSWORD_SHA512: &'static str = "{SHA512}ZzYTXW02PU1y/z4tXXBmoXSJihXhpnaTODYof7GpLfjkFycWLBKLdHkP4bRWEkYJsD3HjgTn2drxj8nzgBUckQ==";
    const TEST_PASSWORD_SHA512_BAD: &'static str = "{SHA512}ZzYTXW02PU1y/z4tXXBmoXSJihXhpnaTODYof7GpLfjkFycWLBKLdHkP4bRWEkYJsD3HjgTn2drxj8nzgAUckQ==";

    #[test]
    fn test_sha256_hash_and_verify() {
        let test_hash = Hash::new(&TEST_PASSWORD, Scheme::SHA256);
        assert_eq!(test_hash.verify(TEST_PASSWORD), true);
    }

    #[test]
    fn test_ssha256_hash_and_verify() {
        let test_hash = Hash::new(&TEST_PASSWORD, Scheme::SSHA256);
        assert_eq!(test_hash.verify(TEST_PASSWORD), true);
    }

    #[test]
    fn test_sha512_hash_and_verify() {
        let test_hash = Hash::new(&TEST_PASSWORD, Scheme::SHA512);
        assert_eq!(test_hash.verify(TEST_PASSWORD), true);
    }

    #[test]
    fn test_ssha512_hash_and_verify() {
        let test_hash = Hash::new(&TEST_PASSWORD, Scheme::SSHA512);
        assert_eq!(test_hash.verify(TEST_PASSWORD), true);
    }

    #[test]
    fn test_find_hash() {
        let mut hashes = vec![
            Hash::new("AnotherTestPassword", Scheme::SSHA512),
            Hash::new("AndAnotherTestPassword", Scheme::SHA512),
        ];

        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), None);
        let ssha512_hash = Hash::new(TEST_PASSWORD, Scheme::SSHA512);
        hashes.insert(1, ssha512_hash.clone());
        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), Some(&ssha512_hash));

        assert_eq!(find_hash(TEST_PASSWORD2, &mut hashes), None);
        let sha512_hash = Hash::new(TEST_PASSWORD2, Scheme::SHA512);
        hashes.push(sha512_hash.clone());
        assert_eq!(find_hash(TEST_PASSWORD2, &mut hashes), Some(&sha512_hash));
    }

    #[test]
    fn test_display_and_tryfrom() {
        let ssha512_hash = Hash::new(TEST_PASSWORD, Scheme::SSHA512);
        let hash_string = ssha512_hash.to_string();
        assert_eq!(Hash::try_from(hash_string.as_str()), Ok(ssha512_hash));

        let sha512_hash = Hash::new(TEST_PASSWORD, Scheme::SHA512);
        let hash_string = sha512_hash.to_string();
        assert_eq!(Hash::try_from(hash_string.as_str()), Ok(sha512_hash));

        assert_eq!(
            Hash::try_from("{INVALID}HASHDATA"),
            Err("unknown scheme: INVALID".to_string())
        );
        assert_eq!(Hash::try_from("{SHA512}"), Err("empty hash".to_string()));
    }

    #[test]
    fn test_verify_password() {
        let ssha512_hash = Hash::try_from(TEST_PASSWORD_SSHA512).unwrap();
        let ssha512_hash_bad = Hash::try_from(TEST_PASSWORD_SSHA512_BAD).unwrap();
        assert_eq!(ssha512_hash.verify(TEST_PASSWORD), true);
        assert_eq!(ssha512_hash_bad.verify(TEST_PASSWORD), false);

        let sha512_hash = Hash::try_from(TEST_PASSWORD_SHA512).unwrap();
        let sha512_hash_bad = Hash::try_from(TEST_PASSWORD_SHA512_BAD).unwrap();
        assert_eq!(sha512_hash.verify(TEST_PASSWORD), true);
        assert_eq!(sha512_hash_bad.verify(TEST_PASSWORD), false);
    }
}
