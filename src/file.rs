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

use crate::hashlib::{Hash, Scheme};
use crate::{AuthError, AuthResult, CredentialsVerify, CredentialsVerifyCache};

use bincode;
use fs2::FileExt;
use log::{debug, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use std::collections::HashMap;
use std::fs::File;
use std::io::Seek;
use std::os::unix::prelude::OpenOptionsExt;
use std::time::SystemTime;

const DEFAULT_VERIFY_CACHE_FILE: &str = "/tmp/dovecot-auth-verify.cache";

pub trait BinaryCacheFile
where
    Self: Serialize + DeserializeOwned,
{
    fn load_from_file(file: &File) -> AuthResult<Self> {
        debug!("trying to get shared lock on file {:?}", file);
        file.lock_shared()?;
        debug!("read file and deserialize content");
        let instance: Self =
            bincode::deserialize_from(file).map_err(|err| AuthError::TempFail(err.to_string()))?;
        debug!("unlock file");
        file.unlock()?;
        Ok(instance)
    }

    fn save_to_file(&self, mut file: File) -> AuthResult<()> {
        debug!("trying to get exclusive lock on file {:?}", file);
        file.lock_exclusive()?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.set_len(0)?;
        debug!("serialize and write data to file");
        bincode::serialize_into(&mut file, self)
            .map_err(|err| AuthError::TempFail(err.to_string()))?;
        debug!("unlock file");
        file.unlock()?;
        Ok(())
    }
}

impl<T> BinaryCacheFile for T where T: Serialize + DeserializeOwned {}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FileCacheVerifyConfig {
    pub cache_file: Option<String>,
    pub verify_interval: u64,
    pub max_lifetime: u64,
    pub hash_scheme: Option<Scheme>,
    pub allow_expired_on_error: bool,
}

impl Default for FileCacheVerifyConfig {
    fn default() -> Self {
        Self {
            cache_file: Some(String::from(DEFAULT_VERIFY_CACHE_FILE)),
            verify_interval: 60,
            max_lifetime: 86400,
            hash_scheme: Some(Scheme::SSHA512),
            allow_expired_on_error: false,
        }
    }
}

type Cache = HashMap<String, HashMap<String, SystemTime>>;

pub struct FileCacheVerifyModule {
    config: FileCacheVerifyConfig,
    cache: Cache,
    cache_file: String,
    changed: bool,
    module: Box<dyn CredentialsVerify>,
    hash_scheme: Scheme,
}

impl FileCacheVerifyModule {
    pub fn new(config: FileCacheVerifyConfig, module: Box<dyn CredentialsVerify>) -> Self {
        let hash_scheme = config
            .hash_scheme
            .as_ref()
            .cloned()
            .unwrap_or(Scheme::SSHA512);
        let cache_file = config
            .cache_file
            .as_ref()
            .cloned()
            .unwrap_or(DEFAULT_VERIFY_CACHE_FILE.to_string());
        let cache = match File::open(&cache_file) {
            Ok(file) => Cache::load_from_file(&file).unwrap_or_else(|err| {
                warn!("unable to deserialize cache: {err}");
                Default::default()
            }),
            Err(err) => {
                debug!("unable to load cache file: {err}");
                Default::default()
            }
        };

        Self {
            config,
            cache,
            cache_file,
            changed: false,
            module,
            hash_scheme,
        }
    }
}

impl CredentialsVerifyCache for FileCacheVerifyModule {
    fn hash(&self, password: &str) -> Hash {
        Hash::new(password, &self.hash_scheme)
    }

    fn get_hashes(&self, user: &str) -> AuthResult<(Vec<Hash>, Vec<Hash>)> {
        let mut verified_hashes = Vec::new();
        let mut expired_hashes = Vec::new();
        let now = SystemTime::now();
        if let Some(hashes) = self.cache.get(user) {
            for (hash, last_verified) in hashes {
                if let Ok(duration) = now.duration_since(*last_verified).map(|d| d.as_secs()) {
                    if let Ok(hash) = Hash::try_from(hash.as_str()) {
                        if duration <= self.config.verify_interval {
                            verified_hashes.push(hash);
                        } else if duration <= self.config.max_lifetime {
                            expired_hashes.push(hash);
                        }
                    }
                }
            }
        }
        Ok((verified_hashes, expired_hashes))
    }

    fn insert(&mut self, username: &str, hash: Hash) -> AuthResult<()> {
        match self.cache.get_mut(username) {
            Some(hashes) => {
                hashes.insert(hash.to_string(), SystemTime::now());
            }
            None => {
                let mut hashes = HashMap::new();
                hashes.insert(hash.to_string(), SystemTime::now());
                self.cache.insert(username.to_string(), hashes);
            }
        };
        self.changed = true;
        Ok(())
    }

    fn delete(&mut self, user: &str, hash: &Hash) -> AuthResult<()> {
        let mut cleanup = false;
        if let Some(hashes) = self.cache.get_mut(user) {
            if hashes.remove(&hash.to_string()).is_some() {
                self.changed = true;
            }
            if hashes.is_empty() {
                cleanup = true;
            }
        }
        if cleanup {
            self.cache.retain(|_, hashes| !hashes.is_empty());
        }
        Ok(())
    }

    fn cleanup(&mut self) -> AuthResult<()> {
        let now = SystemTime::now();
        let mut cleanup = false;
        for hashes in self.cache.values_mut() {
            hashes.retain(
                |_, last_verified| match now.duration_since(*last_verified) {
                    Ok(duration) => {
                        let valid = duration.as_secs() <= self.config.max_lifetime;
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
            self.cache.retain(|_, hashes| !hashes.is_empty());
        }

        Ok(())
    }

    fn save(&self) -> AuthResult<()> {
        if self.changed {
            let file = File::options().write(true).create(true).mode(0o622).open(&self.cache_file)?;
            self.cache.save_to_file(file)?;
        }
        Ok(())
    }

    fn module(&mut self) -> &mut Box<dyn CredentialsVerify> {
        &mut self.module
    }

    fn allow_expired_on_error(&self) -> bool {
        self.config.allow_expired_on_error
    }
}
