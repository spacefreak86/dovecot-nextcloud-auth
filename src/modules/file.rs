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

use crate::{hashlib, AuthError, AuthResult, CredentialsVerify, CredentialsVerifyCache};

use bincode;
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;

const DEFAULT_VERIFY_CACHE_FILE: &str = "/tmp/dovecot-auth-verify.cache";

pub trait BinaryCacheFile
where
    Self: Serialize + DeserializeOwned,
{
    fn load_from_file(file: File) -> AuthResult<Self> {
        file.lock_shared()?;
        let instance: Self = bincode::deserialize_from(&file)
            .map_err(|err| AuthError::TempFail(format!("unable to deserialize: {err}",)))?;
        file.unlock()?;
        Ok(instance)
    }

    fn save_to_file(&self, mut file: File) -> AuthResult<()> {
        file.lock_exclusive()?;
        file.set_len(0)?;
        bincode::serialize_into(&mut file, self)
            .map_err(|err| AuthError::TempFail(err.to_string()))?;
        file.unlock()?;
        Ok(())
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

type Cache = HashMap<String, HashMap<String, SystemTime>>;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct VerifyCacheFile {
    cache: Cache,
}

impl std::ops::Deref for VerifyCacheFile {
    type Target = Cache;

    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

impl std::ops::DerefMut for VerifyCacheFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cache
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct VerifyCache {
    cache: VerifyCacheFile,
    changed: bool,
}

impl std::ops::Deref for VerifyCache {
    type Target = VerifyCacheFile;

    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

impl std::ops::DerefMut for VerifyCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cache
    }
}

impl VerifyCache {
    fn load_from_file(file: File) -> AuthResult<Self> {
        let cache = VerifyCacheFile::load_from_file(file)?;
        Ok(Self {
            cache,
            changed: false,
        })
    }

    fn save_to_file(&self, file: File) -> AuthResult<()> {
        self.cache.save_to_file(file)
    }
}

impl VerifyCache {
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

    fn cleanup(&mut self, max_lifetime: u64) {
        let now = SystemTime::now();
        let mut cleanup = false;
        for hashes in self.cache.values_mut() {
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
            self.cache.retain(|_, hashes| !hashes.is_empty());
        }
    }

    fn delete(&mut self, username: &str, hash: &str) {
        let mut cleanup = false;
        if let Some(hashes) = self.cache.get_mut(username) {
            if hashes.remove(hash).is_some() {
                self.changed = true;
            }
            if hashes.is_empty() {
                cleanup = true;
            }
        }
        if cleanup {
            self.cache.retain(|_, hashes| !hashes.is_empty());
        }
    }
}

pub struct FileCacheVerifyModule {
    config: FileCacheVerifyConfig,
    cache: VerifyCache,
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
        let cache = config
            .cache_file
            .as_ref()
            .map(|path| match File::open(path) {
                Ok(file) => VerifyCache::load_from_file(file).unwrap_or_else(|err| {
                    eprintln!("unable to deserialize cache: {err}");
                    VerifyCache::default()
                }),
                Err(_) => VerifyCache::default(),
            })
            .unwrap_or_default();

        Self {
            config,
            cache,
            cache_file,
            module,
            hash_scheme,
        }
    }
}

impl CredentialsVerifyCache for FileCacheVerifyModule {
    fn hash(&self, password: &str) -> String {
        hashlib::hash(password, &self.hash_scheme)
    }

    fn get_hashes(&self, user: &str) -> AuthResult<(Vec<String>, Vec<String>)> {
        Ok(self
            .cache
            .get_hashes(user, self.config.verify_interval, self.config.max_lifetime))
    }

    fn insert(&mut self, username: &str, hash: &str) -> AuthResult<()> {
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
        self.cache.changed = true;
        Ok(())
    }

    fn delete(&mut self, user: &str, hash: &str) -> AuthResult<()> {
        self.cache.delete(user, hash);
        Ok(())
    }

    fn cleanup(&mut self) -> AuthResult<()> {
        self.cache.cleanup(self.config.max_lifetime);
        Ok(())
    }

    fn save(&self) {
        if self.cache.changed {
            match File::options().write(true).open(&self.cache_file) {
                Ok(file) => {
                    self.cache.save_to_file(file).unwrap_or_else(|err| {
                        eprintln!("unable to write cache_file: {err}");
                    });
                }
                Err(_) => match File::create(&self.cache_file) {
                    Ok(file) => {
                        if let Ok(metadata) = file.metadata() {
                            metadata.permissions().set_mode(0o600);
                        }
                        self.cache.save_to_file(file).unwrap_or_else(|err| {
                            eprintln!("unable to write cache_file: {err}");
                        });
                    }
                    Err(err) => eprintln!("unable to create cache_file: {err}"),
                },
            };
        }
    }

    fn module(&mut self) -> &mut Box<dyn CredentialsVerify> {
        &mut self.module
    }

    fn allow_expired_on_error(&self) -> bool {
        self.config.allow_expired_on_error
    }
}
