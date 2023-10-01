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

use base64::{engine::general_purpose, Engine as _};
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha512};
use log::warn;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Scheme {
    SHA512,
    SSHA512,
}

impl Scheme {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SHA512 => "SHA512",
            Self::SSHA512 => "SSHA512",
        }
    }
}

fn ssha512(password: &[u8], salt: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(password);
    hasher.update(salt);
    let hash = hasher.finalize();
    let salted_hash = [&hash, salt].concat();
    format!(
        "{{{}}}{}",
        Scheme::SSHA512.as_str(),
        general_purpose::STANDARD.encode(salted_hash)
    )
}

fn sha512(password: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(password);
    let hash = hasher.finalize();
    format!(
        "{{{}}}{}",
        Scheme::SHA512.as_str(),
        general_purpose::STANDARD.encode(hash)
    )
}

pub fn hash(password: &str, scheme: &Scheme) -> String {
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

pub fn verify_hash(password: &str, hash: &str) -> bool {
    let mut hash1 = String::new();
    if hash.starts_with("{SSHA512}") {
        match general_purpose::STANDARD.decode(hash.trim_start_matches("{SSHA512}")) {
            Ok(decoded_hash) => {
                if decoded_hash.len() < 65 {
                    return false;
                }
                let salt = &decoded_hash[64..];
                hash1 = ssha512(password.as_bytes(), salt)
            }
            _ => warn!("base64: unable to decode hash: {hash}"),
        }
    } else if hash.starts_with("{SHA512}") {
        hash1 = sha512(password.as_bytes());
    } else {
        warn!("unknown hash type: {hash}");
    }
    hash == hash1
}

pub fn find_hash<H: AsRef<str>>(password: &str, hash_list: &mut Vec<H>) -> Option<H> {
    if let Some(index) = hash_list
        .iter()
        .position(|hash| verify_hash(password, hash.as_ref()))
    {
        return Some(hash_list.remove(index));
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::hashlib::{find_hash, hash, verify_hash, Scheme};

    const TEST_PASSWORD: &'static str = "TestPass ä?=%*@+-ç£{}()!#\"'~`";

    #[test]
    fn test_ssha512_hash_and_verify() {
        let test_hash = hash(&TEST_PASSWORD, &Scheme::SSHA512);
        assert_eq!(verify_hash(TEST_PASSWORD, &test_hash), true);
    }

    #[test]
    fn test_sha512_hash_and_verify() {
        let test_hash = hash(&TEST_PASSWORD, &Scheme::SHA512);
        assert_eq!(verify_hash(TEST_PASSWORD, &test_hash), true);
    }

    #[test]
    fn test_get_matching_hash() {
        let ssha512_hash = hash(TEST_PASSWORD, &Scheme::SSHA512);
        let sha512_hash = hash(TEST_PASSWORD, &Scheme::SHA512);

        let mut hashes = vec![
            hash("AnotherTestPassword", &Scheme::SSHA512),
            ssha512_hash.clone(),
            hash("AndAnotherTestPassword", &Scheme::SHA512),
        ];
        assert_eq!(
            find_hash(TEST_PASSWORD, &mut hashes),
            Some(ssha512_hash)
        );
        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), None);

        hashes.push(sha512_hash.clone());
        assert_eq!(
            find_hash(TEST_PASSWORD, &mut hashes),
            Some(sha512_hash)
        );
        assert_eq!(find_hash(TEST_PASSWORD, &mut hashes), None);
    }
}
