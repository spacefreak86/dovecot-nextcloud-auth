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

pub(crate) use super::{hashlib, AuthResult, DovecotUser, Error};

pub trait CredentialsLookup {
    fn credentials_lookup(&self, user: &mut DovecotUser) -> AuthResult<()>;
}

pub trait CredentialsVerify {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()>;
}

pub trait CredentialsUpdate {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<()>;
}

#[derive(Debug, Default, Clone)]
pub struct InternalVerifyModule {}

impl InternalVerifyModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialsVerify for InternalVerifyModule {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        if user.password.is_empty() {
            return Err(Error::PermFail);
        }

        match hashlib::verify_hash(password, &user.password) {
            true => Ok(()),
            false => Err(Error::PermFail),
        }
    }
}
