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

pub mod db;
pub mod http;

pub(crate) use super::{DovecotUser, AuthResult, Error, hashlib};

pub trait CredentialsLookup {
    fn credentials_lookup(&self, user: &mut DovecotUser) -> AuthResult<()>;
}

pub trait CredentialsVerify {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()>;
}

pub trait CredentialsUpdate {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<()>;
}


pub struct InternalVerifyModule {}

impl CredentialsVerify for InternalVerifyModule {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        match hashlib::verify_hash(password, &user.password) {
            true => Ok(()),
            false => Err(Error::PermFail)
        }
    }
}