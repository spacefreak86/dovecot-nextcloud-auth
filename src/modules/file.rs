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
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;

const DEFAULT_VERIFY_CACHE_FILE: &str = "/tmp/dovecot-auth-verify.cache";

pub trait BinaryCacheFile
where
    Self: Serialize + DeserializeOwned,
{
    fn load_from_file(file: &File) -> AuthResult<Self> {
        file.lock_shared()?;
        let instance = bincode::deserialize_from(file)
            .map_err(|err| Error::TempFail(format!("unable to deserialize: {err}",)))?;
        file.unlock()?;
        Ok(instance)
    }

    fn save_to_file(&self, mut file: &File) -> AuthResult<()> {
        match bincode::serialize(self) {
            Ok(contents) => {
                file.lock_exclusive()?;
                file.set_len(contents.len() as u64)?;
                file.write_all(&contents)?;
                file.unlock()?;
                Ok(())
            }
            Err(err) => Err(Error::TempFail(err.to_string())),
        }
    }
}

impl<T> BinaryCacheFile for T where T: Serialize + DeserializeOwned {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileCacheVerifyConfig {
    pub cache_file: Option<String>,
    pub verify_interval: u64,
    pub max_lifetime: u64,
    pub hash_scheme: Option<hashlib::Scheme>,
    pub allow_expired_on_error: bool,
}

impl Default for FileCacheVerifyConfig {
    fn default() -> Self {
        Self {
            cache_file: Some(String::from(DEFAULT_VERIFY_CACHE_FILE)),
            verify_interval: 60,
            max_lifetime: 86400,
            hash_scheme: Some(hashlib::Scheme::SSHA512),
            allow_expired_on_error: false,
        }
    }
}

pub struct FileCacheVerifyModule {
    config: FileCacheVerifyConfig,
    cache_file: String,
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
        let cache_file = config
            .cache_file
            .as_ref()
            .cloned()
            .unwrap_or(DEFAULT_VERIFY_CACHE_FILE.to_string());
        Self {
            config,
            cache_file,
            module,
            hash_scheme,
        }
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
struct VerifyCacheFile {
    cache: HashMap<String, HashMap<String, SystemTime>>,
    #[serde(skip_serializing, default)]
    changed: bool,
}

impl VerifyCacheFile {
    fn insert(&mut self, username: &str, hash: String) {
        match self.cache.get_mut(username) {
            Some(hashes) => {
                hashes.insert(hash, SystemTime::now());
            }
            None => {
                let mut hashes = HashMap::new();
                hashes.insert(hash, SystemTime::now());
                self.cache.insert(username.to_string(), hashes);
            }
        };
        self.changed = true;
    }

    fn get_hashes(
        &self,
        username: &str,
        verify_interval: u64,
        max_lifetime: u64,
    ) -> (Vec<String>, Vec<String>) {
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
        let mut cleanup = false;
        for (_, hashes) in self.cache.iter_mut() {
            hashes.retain(
                |_, last_verified| match now.duration_since(*last_verified) {
                    Ok(duration) => {
                        let valid = duration.as_secs() <= max_lifetime;
                        if valid == false {
                            self.changed = true;
                        }
                        valid
                    }
                    Err(_) => {
                        self.changed = true;
                        false
                    }
                },
            );
            if hashes.is_empty() {
                cleanup = true;
            }
        }
        if cleanup {
            self.cleanup();
        }
    }

    fn delete_hash(&mut self, username: &str, hash: &str) {
        if let Some(hashes) = self.cache.get_mut(username) {
            if hashes.remove(hash).is_some() {
                self.changed = true;
            }
            if hashes.is_empty() {
                self.cleanup();
            }
        }
    }

    fn cleanup(&mut self) {
        self.cache.retain(|_, hashes| !hashes.is_empty());
    }
}

impl CredentialsVerify for FileCacheVerifyModule {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        let mut cache = match File::open(&self.cache_file) {
            Ok(file) => VerifyCacheFile::load_from_file(&file).unwrap_or_default(),
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
                let hash =
                    expired_hash.unwrap_or_else(|| hashlib::hash(password, &self.hash_scheme));
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
            match File::open(&self.cache_file) {
                Ok(file) => {
                    cache.save_to_file(&file).unwrap_or_else(|err| {
                        eprintln!("unable to write cache_file: {err}");
                    });
                }
                Err(_) => match File::create(&self.cache_file) {
                    Ok(file) => {
                        if let Ok(metadata) = file.metadata() {
                            metadata.permissions().set_mode(0o600);
                        }
                        cache.save_to_file(&file).unwrap_or_else(|err| {
                            eprintln!("unable to write cache_file: {err}");
                        });
                    },
                    Err(err) => eprintln!("unable to create cache_file: {err}"),
                },
            };
        }

        res
    }
}
