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

use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;
use std::{fs::File, io::Read, os::unix::io::FromRawFd, };
use std::ffi::CString;
use std::{result,env};
use config_file::FromConfigFile;
use serde::Deserialize;
use nix::unistd::execvp;
use error::AuthError;


#[derive(Eq, PartialEq, Hash)]
enum UserField {
    User,
    Password,
    Home,
    Mail,
    Uid,
    Gid,
    QuotaRule,
}

impl TryFrom<&str> for UserField {
    type Error = AuthError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "user" => Ok(Self::User),
            "password" => Ok(Self::Password),
            "home" => Ok(Self::Home),
            "mail" => Ok(Self::Mail),
            "uid" => Ok(Self::Uid),
            "gid" => Ok(Self::Gid),
            "quota_rule" => Ok(Self::QuotaRule),
            _ => Err(AuthError::Temp("invalid field name".to_string())),
        }
    }
}

#[derive(Default)]
struct DovecotUser {
    user: String,
    password: String,
    home: Option<String>,
    mail: Option<String>,
    uid: Option<String>,
    gid: Option<String>,
    quota_rule: Option<String>,
}

impl DovecotUser {
    fn new() -> Self {
        Self::default()
    }

    fn value_mut(&mut self, field: UserField) -> &mut String {
        match field {
            UserField::User => &mut self.user,
            UserField::Password => &mut self.password,
            UserField::Home => self.home.get_or_insert(String::new()),
            UserField::Mail => self.mail.get_or_insert(String::new()),
            UserField::Uid => self.uid.get_or_insert(String::new()),
            UserField::Gid => self.gid.get_or_insert(String::new()),
            UserField::QuotaRule => self.quota_rule.get_or_insert(String::new()),
        }
    }

    pub fn get_env_vars(&self) -> HashMap<&str, String> {
        let mut extra: Vec<&str> = Vec::new();
        let mut map: HashMap<&str, String> = HashMap::new();

        map.insert("USER", self.user.clone());

        if let Some(home) = self.home.clone() {
            map.insert("HOME", home);
        }

        if let Some(mail) = self.mail.clone() {
            map.insert("userdb_mail", mail);
            extra.push("userdb_mail");
        }

        if let Some(uid) = self.uid.clone() {
            map.insert("userdb_uid", uid);
            extra.push("userdb_uid");
        }

        if let Some(gid) = self.gid.clone() {
            map.insert("userdb_gid", gid);
            extra.push("userdb_gid");
        }

        if let Some(quota_rule) = self.quota_rule.clone() {
            map.insert("userdb_quota_rule", quota_rule);
            extra.push("userdb_quota_rule");
        }

        if !extra.is_empty() {
            map.insert("EXTRA", extra.join(" "));
        }
        map
    }
}

impl From<HashMap<String, String>> for DovecotUser {
    fn from(map: HashMap<String, String>) -> Self {
        let mut user = Self::new();
        for (key, value) in map.into_iter() {
            if let Ok(field) = UserField::try_from(key.as_str()) {
                *user.value_mut(field) = value;
            }
        }
        user
    }
}

fn verify_webdav_credentials(username: &str, password: &str, url: &str) -> result::Result<bool, AuthError> {
    let authorization = String::from("Basic ") + &general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    match ureq::request("PROPFIND", url).set("Authorization", &authorization).call() {
        Ok(res) => {
            let code = res.status();
            if code == 207 {
                Ok(true)
            } else {
                Err(AuthError::Temp(format!("unexpected http response: {} {}", code, res.status_text())))
            }
        },
        Err(ureq::Error::Status(code, res)) => {
            if code == 401 {
                Ok(false)
            } else {
                Err(AuthError::Temp(format!("unexpected http error response: {} {}", code, res.status_text())))
            }
        },
        Err(err) => Err(AuthError::Temp(format!("unable to reach server: {}", err)))
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

        for (env_var, value) in user.get_env_vars() {
            env::set_var(env_var, value);
        }

        match execvp(&c_reply_bin, &c_args) {
            Ok(_) => Ok(()),
            Err(err) => Err(AuthError::Temp(format!("unable to call reply binary: {}", err.desc())))
        }
    }

    fn credentials_lookup(&self, username: &str) -> result::Result<DovecotUser, AuthError> {
        match db::get_user(username, &self.conn_pool, &self.config.user_query, &["user", "password", "home", "mail", "uid", "gid", "quota_rule"])? {
            Some(user) => Ok(DovecotUser::from(user)),
            None => Err(AuthError::NoUser)
        }
    }

    fn credentials_verify(&self, username: &str, password: &str) -> result::Result<(), AuthError> {
        if self.config.cache_cleanup {
            db::delete_dead_hashes(self.config.cache_max_lifetime, &self.conn_pool, &self.config.cache_table)?;
        }
        let mut verified_hashes: Vec<String> = Vec::new();
        let mut expired_hashes: Vec<String> = Vec::new();
        for (hash, last_verify) in db::get_hashes(username, &self.conn_pool, &self.config.cache_table, self.config.cache_max_lifetime)? {
            if last_verify <= self.config.cache_verify_interval {
                verified_hashes.push(hash);
            } else if last_verify > self.config.cache_verify_interval && last_verify <= self.config.cache_max_lifetime {
                expired_hashes.push(hash);
            }
        }

        if hashlib::get_matching_hash(password, &verified_hashes).is_some() {
            return Ok(())
        }

        let url = format!("{}/remote.php/dav/files/{}", self.config.nextcloud_url, username);
        match verify_webdav_credentials(username, password, &url) {
            Ok(verify_ok) => {
                // got authentication result from nextcloud
                if verify_ok {
                    let hash: String = match hashlib::get_matching_hash(password, &expired_hashes) {
                        Some(h) => h,
                        None => {
                            hashlib::hash(password, &self.config.hash_scheme).unwrap_or("".to_string())
                        }
                    };
                    if hash.is_empty() {
                        eprintln!("config: hash_scheme: invalid scheme '{}'", &self.config.hash_scheme);
                    } else {
                        db::save_hash(username, &hash, &self.conn_pool, &self.config.cache_table)?;
                    }
                    Ok(())
                } else {
                    let invalid_hash = hashlib::get_matching_hash(password, &expired_hashes);
                    if let Some(hash) = invalid_hash {
                        db::delete_hash(username, &hash, &self.conn_pool, &self.config.cache_table)?;
                    }
                    Err(AuthError::Perm)
                }
            },
            Err(err) => {
                eprintln!("{}", err);
                match hashlib::get_matching_hash(password, &expired_hashes) {
                    Some(_) => {
                        Ok(())
                    },
                    None => {
                        Err(AuthError::Perm)
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
    let credentials: Vec<&str> = input.split('\0').collect();
    if credentials.len() >= 2 {
        Ok((credentials[0].to_string(), credentials[1].to_string()))
    } else {
        Err(AuthError::Temp(format!("did not receive credentials on fd {}", fd)))
    }
}

pub fn authenticate(fd: i32, config_file: &str, reply_bin: &str, test: bool) -> result::Result<(), AuthError> {
    let config = Config::from_config_file(config_file)?;
    let conn_pool = db::get_conn_pool(&config.db_url)?;
    let authenticator = Authenticator {
        config: &config,
        reply_bin: reply_bin.to_string(),
        test,
        conn_pool,
    };
    let (username, password) = credentials_from_fd(fd)?;
    let user: DovecotUser = authenticator.credentials_lookup(&username.to_lowercase())?;
    if env::var("CREDENTIALS_LOOKUP").unwrap_or("".to_string()) == "1" {
        if env::var("AUTHORIZED").unwrap_or("".to_string()) == "1" {
            env::set_var("AUTHORIZED", "2");
        }
    } else {
        if !user.password.is_empty() && !config.update_password_query.is_empty() && !config.update_hash_scheme.is_empty() {
            let hash_prefix: String = format!("{{{}}}", &config.update_hash_scheme);
            if user.password.starts_with(&hash_prefix) && hashlib::verify_hash(&password, &user.password) {
                match hashlib::hash(&password, &config.hash_scheme) {
                    Some(hash) => {
                        db::update_password(&user.user, &hash, &authenticator.conn_pool, &config.update_password_query)?;
                    },
                    None => {
                        eprintln!("config: hash_scheme: invalid scheme '{}'", &config.hash_scheme);
                    }
                }
            }
        }
        let remote_ip = env::var("REMOTE_IP").unwrap_or("".to_string());
        if !remote_ip.is_empty() && !user.password.is_empty() && config.db_auth_hosts.contains(&remote_ip) {
            if !hashlib::verify_hash(&password, &user.password) {
                return Err(AuthError::Perm);
            }
        } else {
            authenticator.credentials_verify(&user.user, &password)?
        }
    }
    authenticator.call_reply_bin(&user)
}
