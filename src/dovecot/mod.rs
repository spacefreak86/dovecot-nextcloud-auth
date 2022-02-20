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
mod hashlib;

use std::collections::HashMap;
use std::{fs::File, io::Read, os::unix::io::FromRawFd, };
use std::ffi::CString;
use config_file::FromConfigFile;
use serde::Deserialize;
use nix::unistd::execvp;
use rand::Rng;
use rand::distributions::Alphanumeric;
use phf::{phf_map, Map};
use ureq;
use error::AuthError;

pub struct DovecotUser<'a> {
    fields: HashMap<&'a str, String>,
}

pub const USER_FIELDS: [&str; 7] = ["username", "password", "home", "mail", "uid", "gid", "quota_rule"];

static USERDB_ENVVAR_MAP: Map<&'static str, &'static str> = phf_map! {
    "username"   => "USER",
    "home"       => "HOME",
    "mail"       => "userdb_mail",
    "uid"        => "userdb_uid",
    "gid"        => "userdb_gid",
    "quota_rule" => "userdb_quota_rule",
};

impl DovecotUser<'_> {
    pub fn new() -> Self {
        let mut user = Self { fields: HashMap::new() };
        for field in USER_FIELDS {
            user.fields.insert(field, String::new());
        }
        user
    }

    pub fn get_env(&self) -> HashMap<String, String> {
        let mut extra: Vec<&str> = Vec::new();
        let mut env: HashMap<String, String> = HashMap::new();
        for field in self.fields.keys() {
            if self.fields[field].len() > 0 {
                let env_var = USERDB_ENVVAR_MAP[&field];
                if env_var.starts_with("userdb_") {
                    extra.push(env_var);
                }
                env.insert(env_var.to_string(), self.fields[field].clone());
            }
        }
        if extra.len() > 0 {
            env.insert("EXTRA".to_string(), extra.join(" "));
        }
        env
    }
}

impl From<HashMap<String, String>> for DovecotUser<'_> {
    fn from(map: HashMap<String, String>) -> Self {
        let mut user = Self::new();
        for field in USER_FIELDS {
            if map.contains_key(field) {
                user.fields.insert(field, map.get(field).unwrap().to_string());
            }
        }
        user
    }
}

fn verify_webdav_credentials(username: &str, password: &str, url: &str) -> std::result::Result<bool, AuthError> {
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

struct Authenticator {
    config: Config,
    reply_bin: String,
    test: bool,
    conn_pool: mysql::Pool,
}

impl Authenticator {
    fn call_reply_bin(&self, user: &DovecotUser) -> std::result::Result<(), AuthError> {
        let c_reply_bin = CString::new(self.reply_bin.clone()).expect("CString::new failed");
        let mut skip_args = 1;
        if self.test {
            skip_args += 1;
        }
        let args: Vec<String> = std::env::args().skip(skip_args).collect();
        let mut c_args: Vec<CString> = Vec::new();
        for arg in args {
            c_args.push(CString::new(arg).expect("CString:: new failed"));
        }

        for (env_var, value) in user.get_env() {
            std::env::set_var(env_var, value);
        }

        match execvp(&c_reply_bin, &c_args) {
            Ok(_) => Ok(()),
            Err(err) => Err(AuthError::TempError(format!("unable to call reply binary: {}", err.desc())))
        }
    }

    fn credentials_lookup(&self, username: &str) -> std::result::Result<DovecotUser, AuthError> {
        match db::get_user(&username, &self.conn_pool, &self.config.user_query, &USER_FIELDS)? {
            Some(user) => {
                Ok(DovecotUser::from(user))
            },
            None => {
                Err(AuthError::NoUserError)
            }
        }
    }

    fn credentials_verify(&self, username: &str, password: &str) -> std::result::Result<(), AuthError> {
        // credentials verify
        if self.config.cache_cleanup {
            db::delete_dead_hashes(self.config.cache_max_lifetime, &self.conn_pool, &self.config.cache_table)?;
        }
        let mut verified_hashes: Vec<String> = Vec::new();
        let mut expired_hashes: Vec<String> = Vec::new();
        for (hash, last_verify) in db::get_hashes(&username, &self.conn_pool, &self.config.cache_table, self.config.cache_max_lifetime)? {
            if last_verify <= self.config.cache_verify_interval {
                verified_hashes.push(hash);
            } else if last_verify > self.config.cache_verify_interval && last_verify <= self.config.cache_max_lifetime {
                expired_hashes.push(hash);
            }
        }

        if hashlib::get_matching_hash(&password, &verified_hashes).is_some() {
            return Ok(())
        }

        let url = format!("{}/remote.php/dav/files/{}", self.config.nextcloud_url, username);
        match verify_webdav_credentials(&username, &password, &url) {
            Ok(verify_ok) => {
                // got authentication result from nextcloud
                if verify_ok {
                    let hash = match hashlib::get_matching_hash(&password, &expired_hashes) {
                        Some(h) => h,
                        None => {
                            let salt: String = rand::thread_rng().sample_iter(&Alphanumeric).take(5).map(char::from).collect();
                            hashlib::ssha512(&password, &salt)
                        }
                    };
                    db::save_hash(&username, &hash, &self.conn_pool, &self.config.cache_table)?;
                    Ok(())
                } else {
                    Err(AuthError::PermError)
                }
            },
            Err(err) => {
                eprintln!("{}", err.to_string());
                match hashlib::get_matching_hash(&password, &expired_hashes) {
                    Some(_) => {
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

fn credentials_from_fd(fd: i32) -> std::result::Result<(String, String), AuthError> {
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

fn get_env_var(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => String::new()
    }
}

pub fn authenticate(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> std::result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let conn_pool = db::get_conn_pool(&config.db_url)?;
    let authenticator = Authenticator {
        config: config,
        reply_bin: reply_bin.to_string(),
        test: test,
        conn_pool: conn_pool,
    };
    let (username, password) = credentials_from_fd(fd)?;
    let user: DovecotUser = authenticator.credentials_lookup(&username)?;
    if get_env_var("CREDENTIALS_LOOKUP") == "1" {
        if get_env_var("AUTHORIZED") == "1" {
            std::env::set_var("AUTHORIZED", "2");
        }
    } else {
        authenticator.credentials_verify(&username, &password)?;
    }

    authenticator.call_reply_bin(&user)
}
