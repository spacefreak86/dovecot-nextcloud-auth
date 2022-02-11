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

use std::{fs::File, io::Read, os::unix::io::FromRawFd, };
use config_file::{FromConfigFile, ConfigFileError};
use serde::Deserialize;

mod db;

#[derive(Deserialize)]
struct Config {
    db_url: String,
    user_query: String,
    nextcloud_url: String,
}

#[derive(Debug)]
pub enum AuthError {
    PermError,
    NoUserError,
    TempError(String),
}

impl std::error::Error for AuthError {}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthError::PermError => write!(f, "PERMFAIL"),
            AuthError::NoUserError => write!(f, "NOUSER"),
            AuthError::TempError(msg) => write!(f, "TEMPFAIL: {}", msg),
        }
    }
}

impl From<ConfigFileError> for AuthError {
    fn from(error: ConfigFileError) -> Self {
        AuthError::TempError(error.to_string().to_owned())
    }
}

impl From<std::io::Error> for AuthError {
    fn from(error: std::io::Error) -> Self {
        AuthError::TempError(error.to_string().to_owned())
    }
}

impl From<mysql::Error> for AuthError {
    fn from(error: mysql::Error) -> Self {
        AuthError::TempError(error.to_string().to_owned())
    }
}

pub fn nextcloud_auth(fd: i32, config_file: &str) -> std::result::Result<db::DovecotUser, AuthError> {
    let config = Config::from_config_file(config_file)?;
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut input = String::new();
    f.read_to_string(&mut input)?;
    let credentials: Vec<&str> = input.split("\0").collect();

    if credentials.len() >= 2 {
        match db::user_lookup(credentials[0], &config.db_url, &config.user_query)? {
            Some(user) => {
                Ok(user)
            },
            None => {
                Err(AuthError::NoUserError)
            }
        }
    } else {
        Err(AuthError::TempError(format!("did not receive credentials on fd {}", fd).to_owned()))
    }
}
