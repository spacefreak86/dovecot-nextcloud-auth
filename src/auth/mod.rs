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
use std::collections::HashMap;
use phf::{phf_map, Map};
use config_file::{FromConfigFile, ConfigFileError};
use serde::Deserialize;
use nix::unistd::execvp;

mod db;

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

static USERDB_ENV_MAP: Map<&'static str, &'static str> = phf_map! {
    "user" => "USER",
    "home" => "HOME",
    "mail" => "userdb_mail",
    "uid"  => "userdb_uid",
    "gid"  => "userdb_gid",
    "quota_rule" => "userdb_quota_rule",
};

fn update_env(user: &HashMap<String, String>) {
    let mut extra: Vec<&str> = Vec::new();
    for (&field, &env_var) in USERDB_ENV_MAP.entries() {
        if &user[field] == "" {
            continue;
        }
        if env_var.starts_with("userdb_") {
            extra.push(env_var);
        }
        std::env::set_var(env_var, &user[field]);
    }
    if extra.len() > 0 {
        std::env::set_var("EXTRA", extra.join(" "))
    }
}

fn call_reply_bin(reply_bin: &str, test: bool) -> std::result::Result<(), AuthError> {
    let c_reply_bin = CString::new(reply_bin).expect("CString::new failed");
    let mut skip_args = 1;
    if test {
        skip_args += 1;
    }
    let args: Vec<String> = std::env::args().skip(skip_args).collect();
    let mut c_args: Vec<CString> = Vec::new();
    for arg in args {
        c_args.push(CString::new(arg).expect("CString:: new failed"));
    }
    match execvp(&c_reply_bin, &c_args) {
        Ok(_) => Ok(()),
        Err(err) => Err(AuthError::TempError(format!("unable to call reply binary: {}", err.desc())))
    }
}

#[derive(Deserialize)]
struct Config {
    db_url: String,
    user_query: String,
    nextcloud_url: String,
}

fn verify_nextcloud_credentials(username: &str, password: &str, url: &str) -> std::result::Result<(), AuthError> {
    let webdav_url = format!("{}/remote.php/dav/files/{}", url, username);
    let authorization = String::from("Basic ") + &base64::encode(format!("{}:{}", username, password));
    match ureq::request("PROPFIND", &webdav_url).set("Authorization", &authorization).call() {
        Ok(_) => {
            Ok(())
        },
        Err(ureq::Error::Status(code, res)) => {
            if code == 401 {
                Err(AuthError::PermError)
            } else {
                Err(AuthError::TempError(format!("unexpected response from nextcloud: {} {}", code, res.status_text()).to_owned()))
            }
        },
        Err(err) => Err(AuthError::TempError(format!("unable to reach nextcloud: {}", err.to_string())))
    }
}

fn get_env_var(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => String::new()
    }
}

pub fn nextcloud_auth(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> std::result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let (username, password) = read_credentials_from_fd(fd)?;

    match db::user_lookup(&username, &config.db_url, &config.user_query)? {
        Some(user) => {
            if get_env_var("CREDENTIALS_LOOKUP") == "1" {
                // credentials lookup
                if get_env_var("AUTHORIZED") == "1" {
                    std::env::set_var("AUTHORIZED", "2");
                }
            } else {
                // credentials verify
                verify_nextcloud_credentials(&username, &password, &config.nextcloud_url)?;
            }
            update_env(&user);
            call_reply_bin(reply_bin, test)?;
            Ok(())
        },
        None => {
            Err(AuthError::NoUserError)
        }
    }
}
