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

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "serde")]
pub mod file;

use crate::{AuthResult, DovecotUser};
use crate::hashlib::{verify_value, find_hash, Hash};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use log::{debug, warn};

pub trait CredentialsLookup {
    fn credentials_lookup(&mut self, user: &mut DovecotUser) -> AuthResult<bool>;
}

pub trait CredentialsVerify {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool>;
}

pub trait CredentialsUpdate {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<bool>;
}

pub trait CredentialsVerifyCache: CredentialsVerify {
    fn hash(&self, password: &str) -> Hash;
    fn get_hashes(&self, user: &str) -> AuthResult<(Vec<Hash>, Vec<Hash>)>;
    fn insert(&mut self, user: &str, hash: Hash) -> AuthResult<()>;
    fn delete(&mut self, user: &str, hash: &Hash) -> AuthResult<()>;
    fn cleanup(&mut self) -> AuthResult<()>;
    fn module(&mut self) -> &mut Box<dyn CredentialsVerify>;
    fn allow_expired_on_error(&self) -> bool;
    fn save(&self) -> AuthResult<()>;
    fn cached_credentials_verify(
        &mut self,
        user: &DovecotUser,
        password: &str,
    ) -> AuthResult<bool> {
        debug!("verify credentials (cached)");
        self.cleanup().unwrap_or_else(|err| {
            warn!("unable to cleanup cache: {err}");
        });

        let (verified_hashes, expired_hashes) =
            self.get_hashes(&user.user).unwrap_or_else(|err| {
                warn!("unable to get hashes from cache: {err}");
                Default::default()
            });
        debug!("verified hashes: {:?}", verified_hashes);
        debug!("try to verify credentials against cached verified hashes");
        if find_hash(password, &verified_hashes).is_some() {
            debug!("verified against cached verified hash successfully");
            return Ok(true);
        }

        let expired_hash = find_hash(password, &expired_hashes).cloned();
        debug!("verify credentials with verification module");
        let res = match self.module().credentials_verify(user, password) {
            Ok(true) => {
                debug!("verification succeeded, insert hash into cache");
                let hash = expired_hash.unwrap_or_else(|| self.hash(password));
                self.insert(&user.user, hash).unwrap_or_else(|err| {
                    warn!("unable to insert hash into cache: {err}");
                });
                Ok(true)
            }
            Ok(false) => {
                if let Some(hash) = expired_hash {
                    self.delete(&user.user, &hash).unwrap_or_else(|err| {
                        warn!("unable to delete hash from cache: {err}");
                    });
                }
                Ok(false)
            }
            Err(err) => match self.allow_expired_on_error() {
                true => {
                    warn!("verification module failed: {err}");
                    warn!("try to verify against expired hashes");
                    match expired_hash {
                        Some(_) => {
                            debug!("verification against expired hashes succeeded");
                            Ok(true)
                        }
                        None => {
                            debug!("verification against expired hashes failed");
                            Ok(false)
                        }
                    }
                }
                false => Err(err),
            },
        };

        if let Err(err) = self.save() {
            warn!("unable to save verify cache: {err}");
        }

        res
    }
}

impl<T: CredentialsVerifyCache> CredentialsVerify for T {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool> {
        self.cached_credentials_verify(user, password)
    }
}

#[derive(Debug, Default, Clone)]
pub struct InternalVerifyModule {}

impl InternalVerifyModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialsVerify for InternalVerifyModule {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool> {
        match Hash::try_from(user.password.as_str()) {
            Ok(hash) => {
                Ok(verify_value(password, &hash))
            },
            Err(_) => Ok(false),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum LookupModule {
    #[cfg(feature = "db")]
    DB(db::DBLookupConfig),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum VerifyModule {
    Internal,
    #[cfg(feature = "http")]
    Http(http::HttpVerifyConfig),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum VerifyCacheModule {
    #[cfg(feature = "db")]
    DB(db::DBCacheVerifyConfig),
    #[cfg(feature = "serde")]
    File(file::FileCacheVerifyConfig),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum UpdateCredentialsModule {
    #[cfg(feature = "db")]
    DB(db::DBUpdateCredentialsConfig),
}