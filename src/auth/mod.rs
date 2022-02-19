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
use rand::Rng;
use rand::distributions::Alphanumeric;

mod db;
mod hasher;

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

fn get_env_var(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => String::new()
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
    cache_table: String,
    user_query: String,
    nextcloud_url: String,
    cache_verify_interval: i64,
    cache_max_lifetime: i64,
}

fn nextcloud_verify_credentials(username: &str, password: &str, nextcloud_url: &str) -> std::result::Result<bool, AuthError> {
    let url = format!("{}/remote.php/dav/files/{}", nextcloud_url, username);
    let authorization = String::from("Basic ") + &base64::encode(format!("{}:{}", username, password));
    match ureq::request("PROPFIND", &url).set("Authorization", &authorization).call() {
        Ok(res) => {
            let code = res.status();
            if code == 207 {
                Ok(true)
            } else {
                Err(AuthError::TempError(format!("unexpected http response: {} {}", code, res.status_text()).to_owned()))
            }
        },
        Err(ureq::Error::Status(code, res)) => {
            if code == 401 {
                Ok(false)
            } else {
                Err(AuthError::TempError(format!("unexpected http error response: {} {}", code, res.status_text()).to_owned()))
            }
        },
        Err(err) => Err(AuthError::TempError(format!("unable to reach server: {}", err.to_string())))
    }
}

pub fn nextcloud_auth(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> std::result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let (username, password) = read_credentials_from_fd(fd)?;
    let conn_pool = db::get_conn_pool(&config.db_url)?;

    if get_env_var("CREDENTIALS_LOOKUP") == "1" {
        // credentials lookup
        match db::get_user(&username, &conn_pool, &config.user_query)? {
            Some(user) => {
                if get_env_var("AUTHORIZED") == "1" {
                    std::env::set_var("AUTHORIZED", "2");
                }
                update_env(&user);
                call_reply_bin(reply_bin, test)?;
                Ok(())
            },
            None => {
                Err(AuthError::NoUserError)
            }
        }
    } else {
        // credentials verify
        let mut no_user: bool = false;
        if config.user_query.len() > 0 {
            match db::get_user(&username, &conn_pool, &config.user_query)? {
                Some(user) => {
                    update_env(&user);
                },
                None => {
                    no_user = true;
                }
            }
        }
        if no_user {
            Err(AuthError::NoUserError)
        } else {
            db::delete_dead_hashes(config.cache_max_lifetime, &conn_pool, &config.cache_table)?;
            let all_hashes = db::get_hashes(&username, &conn_pool, &config.cache_table)?;
            let active_hashes: Vec<&String> = all_hashes.iter().filter_map(|(hash, last_verify)| match last_verify {
                l if l <= &config.cache_verify_interval => Some(hash),
                _ => None
            }).collect();
            match hasher::get_matching_hash(&password, &active_hashes) {
                Some(_) => {
                    call_reply_bin(reply_bin, test)?;
                    Ok(())
                },
                None => {
                    let expired_hashes: Vec<&String> = all_hashes.iter().filter_map(|(hash, last_verify)| match last_verify {
                        l if l > &config.cache_verify_interval && l <= &config.cache_max_lifetime => Some(hash),
                        _ => None
                    }).collect();
                    match nextcloud_verify_credentials(&username, &password, &config.nextcloud_url) {
                        Ok(verify_ok) => {
                            // got authentication result from nextcloud
                            if verify_ok {
                                let hash = match hasher::get_matching_hash(&password, &expired_hashes) {
                                    Some(h) => h,
                                    None => {
                                        let salt: String = rand::thread_rng().sample_iter(&Alphanumeric).take(5).map(char::from).collect();
                                        hasher::ssha512(&password, &salt)
                                    }
                                };
                                db::save_hash(&username, &hash, &conn_pool, &config.cache_table)?;
                                call_reply_bin(reply_bin, test)?;
                                Ok(())
                            } else {
                                Err(AuthError::PermError)
                            }
                        },
                        Err(err) => {
                            eprintln!("{}", err.to_string());
                            match hasher::get_matching_hash(&password, &expired_hashes) {
                                Some(_) => {
                                    call_reply_bin(reply_bin, test)?;
                                    Ok(())
                                },
                                None => {
                                    Err(AuthError::PermError)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
