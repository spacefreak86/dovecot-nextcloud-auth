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
use std::{result,env};
use config_file::FromConfigFile;
use serde::Deserialize;
use nix::unistd::execvp;
use phf::{phf_map, Map};
use ureq;
use error::AuthError;

pub struct DovecotUser<'a> {
    fields: HashMap<&'a str, String>,
}

pub const USER_FIELDS: [&str; 7] = ["user", "password", "home", "mail", "uid", "gid", "quota_rule"];

static USERDB_ENVVAR_MAP: Map<&'static str, &'static str> = phf_map! {
    "user"       => "USER",
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

    pub fn get(&self, field: &str) -> &String {
        &self.fields[field]
    }

    pub fn get_env(&self) -> HashMap<String, String> {
        let mut extra: Vec<&str> = Vec::new();
        let mut env_vars: HashMap<String, String> = HashMap::new();
        for field in USERDB_ENVVAR_MAP.keys() {
            if self.fields[field].is_empty() {
                continue;
            }
            let env_var = USERDB_ENVVAR_MAP[&field];
            if env_var.starts_with("userdb_") {
                extra.push(env_var);
            }
            env_vars.insert(env_var.to_string(), self.fields[field].clone());
        }
        if !extra.is_empty() {
            env_vars.insert("EXTRA".to_string(), extra.join(" "));
        }
        env_vars
    }
}

impl From<HashMap<String, String>> for DovecotUser<'_> {
    fn from(map: HashMap<String, String>) -> Self {
        let mut user = Self::new();
        for field in USER_FIELDS {
            if map.contains_key(field) {
                let value = map.get(field).unwrap().to_string();
                user.fields.insert(field, value);
            }
        }
        user
    }
}

fn verify_webdav_credentials(username: &str, password: &str, url: &str) -> result::Result<bool, AuthError> {
    let authorization = String::from("Basic ") + &base64::encode(format!("{}:{}", username, password));
    match ureq::request("PROPFIND", &url).set("Authorization", &authorization).call() {
        Ok(res) => {
            let code = res.status();
            if code == 207 {
                Ok(true)
            } else {
                Err(AuthError::TempError(format!("unexpected http response: {} {}", code, res.status_text())))
            }
        },
        Err(ureq::Error::Status(code, res)) => {
            if code == 401 {
                Ok(false)
            } else {
                Err(AuthError::TempError(format!("unexpected http error response: {} {}", code, res.status_text())))
            }
        },
        Err(err) => Err(AuthError::TempError(format!("unable to reach server: {}", err.to_string())))
    }
}

#[derive(Deserialize)]
struct Config {
    db_url: String,
    user_query: String,
    update_password_query: String,
    update_hash_scheme: String,
    hash_scheme: String,
    db_auth_hosts: Vec<String>,
    nextcloud_url: String,
    cache_table: String,
    cache_verify_interval: i64,
    cache_max_lifetime: i64,
    cache_cleanup: bool,
}

struct Authenticator<'a> {
    config: &'a Config,
    reply_bin: String,
    test: bool,
    conn_pool: mysql::Pool,
}

impl Authenticator<'_> {
    fn call_reply_bin(&self, user: &DovecotUser) -> result::Result<(), AuthError> {
        let c_reply_bin = CString::new(self.reply_bin.clone()).expect("CString::new failed");
        let mut skip_args = 1;
        if self.test {
            skip_args += 1;
        }
        let args: Vec<String> = env::args().skip(skip_args).collect();
        let mut c_args: Vec<CString> = Vec::new();
        for arg in args {
            c_args.push(CString::new(arg).expect("CString:: new failed"));
        }

        for (env_var, value) in user.get_env() {
            env::set_var(env_var, value);
        }

        match execvp(&c_reply_bin, &c_args) {
            Ok(_) => Ok(()),
            Err(err) => Err(AuthError::TempError(format!("unable to call reply binary: {}", err.desc())))
        }
    }

    fn credentials_lookup(&self, username: &str) -> result::Result<DovecotUser, AuthError> {
        match db::get_user(&username, &self.conn_pool, &self.config.user_query, &USER_FIELDS)? {
            Some(user) => {
                Ok(DovecotUser::from(user))
            },
            None => {
                Err(AuthError::NoUserError)
            }
        }
    }

    fn credentials_verify(&self, username: &str, password: &str) -> result::Result<(), AuthError> {
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
                    let hash: String = match hashlib::get_matching_hash(&password, &expired_hashes) {
                        Some(h) => h,
                        None => {
                            hashlib::hash(&password, &self.config.hash_scheme).unwrap_or("".to_string())
                        }
                    };
                    if hash.is_empty() {
                        eprintln!("config: hash_scheme: invalid scheme '{}'", &self.config.hash_scheme);
                    } else {
                        db::save_hash(&username, &hash, &self.conn_pool, &self.config.cache_table)?;
                    }
                    Ok(())
                } else {
                    let invalid_hash = hashlib::get_matching_hash(&password, &expired_hashes);
                    if invalid_hash.is_some() {
                        db::delete_hash(&username, &invalid_hash.unwrap(), &self.conn_pool, &self.config.cache_table)?;
                    }
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

fn credentials_from_fd(fd: i32) -> result::Result<(String, String), AuthError> {
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut input = String::new();
    f.read_to_string(&mut input)?;
    let credentials: Vec<&str> = input.split("\0").collect();
    if credentials.len() >= 2 {
        Ok((credentials[0].to_string(), credentials[1].to_string()))
    } else {
        Err(AuthError::TempError(format!("did not receive credentials on fd {}", fd)))
    }
}

pub fn authenticate(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let conn_pool = db::get_conn_pool(&config.db_url)?;
    let authenticator = Authenticator {
        config: &config,
        reply_bin: reply_bin.to_string(),
        test: test,
        conn_pool: conn_pool,
    };
    let (username, password) = credentials_from_fd(fd)?;
    let user: DovecotUser = authenticator.credentials_lookup(&username.to_lowercase())?;
    if env::var("CREDENTIALS_LOOKUP").unwrap_or("".to_string()) == "1" {
        if env::var("AUTHORIZED").unwrap_or("".to_string()) == "1" {
            env::set_var("AUTHORIZED", "2");
        }
    } else {
        let pw_hash: &String = user.get("password");
        if !pw_hash.is_empty() && !config.update_password_query.is_empty() && !config.update_hash_scheme.is_empty() {
            let hash_prefix: String = format!("{{{}}}", &config.update_hash_scheme);
            if pw_hash.starts_with(&hash_prefix) && hashlib::verify_hash(&password, &pw_hash) {
                match hashlib::hash(&password, &config.hash_scheme) {
                    Some(hash) => {
                        db::update_password(&user.get("user"), &hash, &authenticator.conn_pool, &config.update_password_query)?;
                    },
                    None => {
                        eprintln!("config: hash_scheme: invalid scheme '{}'", &config.hash_scheme);
                    }
                }
            }
        }
        let remote_ip = env::var("REMOTE_IP").unwrap_or("".to_string());
        if !remote_ip.is_empty() && !pw_hash.is_empty() && config.db_auth_hosts.contains(&remote_ip) {
            if !hashlib::verify_hash(&password, &pw_hash) {
                return Err(AuthError::PermError);
            }
        } else {
            authenticator.credentials_verify(&user.get("user"), &password)?
        }
    }
    authenticator.call_reply_bin(&user)
}
