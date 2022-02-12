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
use std::ffi::CString;
use config_file::{FromConfigFile, ConfigFileError};
use serde::Deserialize;
use nix::unistd::execvp;

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

fn read_credentials_from_fd(fd: i32) -> std::result::Result<(String, String), AuthError> {
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut input = String::new();
    f.read_to_string(&mut input)?;
    let credentials: Vec<&str> = input.split("\0").collect();
    if credentials.len() >= 2 {
        Ok((credentials[0].to_string(), credentials[1].to_string()))
    } else {
        Err(AuthError::TempError(format!("did not receive credentials on fd {}", fd).to_owned()))
    }
}

fn call_reply_bin(reply_bin: &str) -> std::result::Result<(), AuthError> {
    let c_reply_bin = CString::new(reply_bin).expect("CString::new failed");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut c_args: Vec<CString> = Vec::new();
    for arg in args {
        c_args.push(CString::new(arg).expect("CString:: new failed"));
    }
    match execvp(&c_reply_bin, &c_args) {
        Ok(_) => Ok(()),
        Err(err) => Err(AuthError::TempError(format!("unable to call reply_bin: {}", err.desc())))
    }
}

pub fn nextcloud_auth(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> std::result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let (username, password) = read_credentials_from_fd(fd)?;

    match db::user_lookup(&username, &config.db_url, &config.user_query)? {
        Some(user) => {
            if test {
                for field in db::USERDB_FIELDS {
                    println!("{}: {}", field, user[field]);
                }
            }
            call_reply_bin(reply_bin)?;
            Ok(())
        },
        None => {
            Err(AuthError::NoUserError)
        }
    }
}
