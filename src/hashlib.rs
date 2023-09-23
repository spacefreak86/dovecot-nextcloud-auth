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

#[cfg(feature="serde")]
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
            Ok(salt) => hash1 = ssha512(password.as_bytes(), &salt),
            _ => eprintln!("base64: unable to decode hash: {hash}"),
        }
    } else if hash.starts_with("{SHA512}") {
        hash1 = sha512(password.as_bytes());
    } else {
        eprintln!("unknown hash type: {hash}");
    }
    hash == hash1
}

pub fn get_matching_hash(password: &str, hash_list: &Vec<String>) -> Option<String> {
    for hash in hash_list {
        if verify_hash(password, hash) {
            return Some(hash.to_string());
        }
    }
    None
}
