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

use super::{hashlib, AuthResult, CredentialsVerify, DovecotUser, Error};

use bincode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileCacheVerifyConfig {
    pub cache_file: String,
    pub verify_interval: u64,
    pub max_lifetime: u64,
    pub hash_scheme: Option<hashlib::Scheme>,
    pub allow_expired_on_error: bool,
}

impl Default for FileCacheVerifyConfig {
    fn default() -> Self {
        Self {
            cache_file: String::from("/tmp/dovecot-auth.cache"),
            verify_interval: 60,
            max_lifetime: 86400,
            hash_scheme: Some(hashlib::Scheme::SSHA512),
            allow_expired_on_error: false,
        }
    }
}

pub struct FileCacheVerifyModule {
    config: FileCacheVerifyConfig,
    module: Box<dyn CredentialsVerify>,
    hash_scheme: hashlib::Scheme,
}

impl FileCacheVerifyModule {
    pub fn new(config: FileCacheVerifyConfig, module: Box<dyn CredentialsVerify>) -> Self {
        let hash_scheme = config
            .hash_scheme
            .as_ref()
            .cloned()
            .unwrap_or(hashlib::Scheme::SSHA512);
        Self {
            config,
            module,
            hash_scheme,
        }
    }
}

/*
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct CacheEntry {
    hash: String,
    last_verified: SystemTime,
}

impl CacheEntry {
    fn new(hash: String) -> Self {
        Self {
            hash,
            last_verified: SystemTime::now(),
        }
    }

    fn update_last_verified(&mut self) {
        self.last_verified = SystemTime::now();
    }
}

impl AsRef<str> for CacheEntry {
    fn as_ref(&self) -> &str {
        &self.hash
    }
}
*/

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
struct VerifyCacheFile {
    cache: HashMap<String, HashMap<String, SystemTime>>,
    #[serde(skip_serializing, default)]
    changed: bool
}

impl VerifyCacheFile {
    fn insert(&mut self, username: &str, hash: String) {
        match self.cache.get_mut(username) {
            Some(hashes) => {
                hashes.insert(hash, SystemTime::now());
            },
            None => {
                let mut hashes = HashMap::new();
                hashes.insert(hash, SystemTime::now());
                self.cache.insert(username.to_string(), hashes);
            }
        };
        self.changed = true;
    }

    fn get_hashes(&self, username: &str, verify_interval: u64, max_lifetime: u64) -> (Vec<String>, Vec<String>) {
        let mut verified_hashes = Vec::new();
        let mut expired_hashes = Vec::new();
        let now = SystemTime::now();
        if let Some(hashes) = self.cache.get(username) {
            for (hash, last_verified) in hashes {
                if let Ok(duration) = now.duration_since(*last_verified).map(|d| d.as_secs()) {
                    if duration <= verify_interval {
                        verified_hashes.push(hash.clone());
                    } else if duration <= max_lifetime {
                        expired_hashes.push(hash.clone());
                    }
                }
            }
        }
        (verified_hashes, expired_hashes)
    }

    fn delete_hashes(&mut self, max_lifetime: u64) {
        let now = SystemTime::now();
        for (_, hashes) in self.cache.iter_mut() {
            hashes.retain(|_, last_verified| match now.duration_since(*last_verified) {
                Ok(duration) => {
                    let valid = duration.as_secs() <= max_lifetime;
                    if valid == false {
                        self.changed = true;
                    }
                    valid
                },
                Err(_) => {
                    self.changed = true;
                    false
                }
            });
        };
    }

    fn delete_hash(&mut self, username: &str, hash: &str) {
        if let Some(hashes) = self.cache.get_mut(username) {
            if hashes.remove(hash).is_some() {
                self.changed = true;
            }
        }
    }

    fn cleanup(&mut self) {
        self.cache.retain(|_, hashes| !hashes.is_empty());
    }
}

impl CredentialsVerify for FileCacheVerifyModule {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        let mut cache: VerifyCacheFile = match std::fs::read(&self.config.cache_file) {
            Ok(data) => bincode::deserialize(&data).unwrap_or_default(),
            Err(_) => VerifyCacheFile::default(),
        };

        cache.delete_hashes(self.config.max_lifetime);

        let (mut verified_hashes, mut expired_hashes) = cache.get_hashes(
            &user.user,
            self.config.verify_interval,
            self.config.max_lifetime,
        );

        if hashlib::get_matching_hash(password, &mut verified_hashes).is_some() {
            return Ok(());
        }

        let expired_hash = hashlib::get_matching_hash(password, &mut expired_hashes);

        let res = match self.module.credentials_verify(user, password) {
            Ok(_) => {
                let hash = expired_hash.unwrap_or_else(|| hashlib::hash(password, &self.hash_scheme));
                cache.insert(&user.user, hash);
                Ok(())
            }
            Err(err) => match err {
                Error::PermFail => {
                    if let Some(hash) = expired_hash {
                        cache.delete_hash(&user.user, &hash);
                    }
                    Err(err)
                }
                _ => {
                    eprintln!("unable to verify credentials: {err}");
                    match self.config.allow_expired_on_error {
                        true => Ok(expired_hash.map(|_| ()).ok_or(err)?),
                        false => Err(err),
                    }
                }
            },
        };

        if cache.changed {
            cache.cleanup();
            match bincode::serialize(&cache) {
                Ok(contents) => {
                    if let Err(err) = std::fs::write(&self.config.cache_file, contents) {
                        eprintln!("unable to write cache file: {err}");
                    }
                },
                Err(err) => {
                    eprintln!("unable to serialize cache: {err}");
                }
            };
        }

        res
    }
}
