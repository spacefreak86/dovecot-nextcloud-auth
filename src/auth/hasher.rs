// dovecot-nextcloud-auth is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// dovecot-nextcloud-auth is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with dovecot-nextcloud-auth.  If not, see <http://www.gnu.org/licenses/>.

use sha2::{Sha512, Digest};
use base64;

pub fn ssha512(password: &str, salt: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    let hash = hasher.finalize();
    let salted_hash = [&hash, salt.as_bytes()].concat();
    format!("{{SSHA512}}{}", base64::encode(salted_hash))
}

pub fn verify_hash(password: &str, hash: &str) -> bool {
    let mut hash1 = String::new();
    if hash.starts_with("{SSHA512}") {
        let decoded_hash = base64::decode(hash.trim_start_matches("{SSHA512}"));
        if decoded_hash.is_ok() {
            let salt: String = decoded_hash.unwrap()[64..].iter().map(|&c| c as char).collect();
            hash1 = ssha512(password, &salt);
        } else {
            eprintln!("base64: unable to decode hash: {}", hash);
        }
    } else {
        eprintln!("unknown hash type: {}", hash);
    }
    return hash == hash1
}

pub fn get_matching_hash(password: &str, hash_list: &Vec<&String>) -> Option<String> {
    for hash in hash_list {
        if verify_hash(password, hash) {
            return Some(hash.to_string());
        }
    }
    None
}
