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

pub mod error;
mod db;
mod hasher;
mod webdav;

use std::{fs::File, io::Read, os::unix::io::FromRawFd, };
use std::ffi::CString;
use std::collections::HashMap;
use phf::{phf_map, Map};
use config_file::FromConfigFile;
use serde::Deserialize;
use nix::unistd::execvp;
use rand::Rng;
use rand::distributions::Alphanumeric;
use error::AuthError;

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
    cache_cleanup: bool,
}

const USERDB_FIELDS: [&str; 6] = ["password", "home", "mail", "uid", "gid", "quota_rule"];

pub fn nextcloud_auth(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> std::result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let (username, password) = read_credentials_from_fd(fd)?;
    let conn_pool = db::get_conn_pool(&config.db_url)?;

    if get_env_var("CREDENTIALS_LOOKUP") == "1" {
        // credentials lookup
        match db::get_user(&username, &conn_pool, &config.user_query, &USERDB_FIELDS.to_vec())? {
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
            match db::get_user(&username, &conn_pool, &config.user_query, &USERDB_FIELDS.to_vec())? {
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
            if config.cache_cleanup {
                db::delete_dead_hashes(config.cache_max_lifetime, &conn_pool, &config.cache_table)?;
            }
            let mut verified_hashes: Vec<String> = Vec::new();
            let mut expired_hashes: Vec<String> = Vec::new();
            for (hash, last_verify) in db::get_hashes(&username, &conn_pool, &config.cache_table, config.cache_max_lifetime)? {
                if last_verify <= config.cache_verify_interval {
                    verified_hashes.push(hash);
                } else if last_verify > config.cache_verify_interval && last_verify <= config.cache_max_lifetime {
                    expired_hashes.push(hash);
                }
            }
            match hasher::get_matching_hash(&password, &verified_hashes) {
                Some(_) => {
                    call_reply_bin(reply_bin, test)?;
                    Ok(())
                },
                None => {
                    let url = format!("{}/remote.php/dav/files/{}", config.nextcloud_url, username);
                    match webdav::verify_credentials(&username, &password, &url) {
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
