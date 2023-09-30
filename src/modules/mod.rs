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

use crate::{hashlib, AuthResult, DovecotUser};

pub trait CredentialsLookup {
    fn credentials_lookup(&mut self, user: &mut DovecotUser) -> AuthResult<bool>;
}

pub trait CredentialsVerify {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool>;
}

pub trait CredentialsUpdate {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<()>;
}

pub trait CredentialsVerifyCache: CredentialsVerify {
    fn hash(&self, password: &str) -> String;
    fn get_hashes(&self, user: &str) -> AuthResult<(Vec<String>, Vec<String>)>;
    fn insert(&mut self, user: &str, hash: &str) -> AuthResult<()>;
    fn delete(&mut self, user: &str, hash: &str) -> AuthResult<()>;
    fn cleanup(&mut self) -> AuthResult<()>;
    fn module(&mut self) -> &mut Box<dyn CredentialsVerify>;
    fn allow_expired_on_error(&self) -> bool;
    fn save(&self);
    fn cached_credentials_verify(
        &mut self,
        user: &DovecotUser,
        password: &str,
    ) -> AuthResult<bool> {
        self.cleanup().unwrap_or_else(|err| {
            eprintln!("unable to cleanup cache: {err}");
        });

        let (mut verified_hashes, mut expired_hashes) =
            self.get_hashes(&user.user).unwrap_or_else(|err| {
                eprintln!("unable to get hashes from cache: {err}");
                Default::default()
            });
        if hashlib::get_matching_hash(password, &mut verified_hashes).is_some() {
            return Ok(true);
        }

        let expired_hash = hashlib::get_matching_hash(password, &mut expired_hashes);
        let res = match self.module().credentials_verify(user, password) {
            Ok(true) => {
                let hash = expired_hash.unwrap_or_else(|| self.hash(password));
                self.insert(&user.user, &hash).unwrap_or_else(|err| {
                    eprintln!("unable to insert hash into cache: {err}");
                });
                Ok(true)
            }
            Ok(false) => {
                if let Some(hash) = expired_hash {
                    self.delete(&user.user, &hash).unwrap_or_else(|err| {
                        eprintln!("unable to delete hash from cache: {err}");
                    });
                }
                Ok(false)
            }
            Err(err) => match self.allow_expired_on_error() {
                true => Ok(expired_hash.is_some()),
                false => Err(err),
            },
        };

        self.save();

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
        if user.password.is_empty() {
            return Ok(false);
        }

        Ok(hashlib::verify_hash(password, &user.password))
    }
}
