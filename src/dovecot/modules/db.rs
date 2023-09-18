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

use super::{CredentialsLookup, CredentialsVerify, CredentialsUpdate, DovecotUser, AuthResult, Error, hashlib};

use mysql::*;
use mysql::prelude::*;
use serde::Deserialize;

impl From<mysql::Error> for Error {
    fn from(error: mysql::Error) -> Self {
        Error::TempFail(error.to_string())
    }
}

impl From<mysql::UrlError> for Error {
    fn from(error: mysql::UrlError) -> Self {
        Error::TempFail(error.to_string())
    }
}

impl From<mysql::FromValueError> for Error {
    fn from(error: mysql::FromValueError) -> Self {
        Error::TempFail(error.to_string())
    }
}

pub fn get_conn_pool(url: &str) -> AuthResult<Pool> {
    let opts = Opts::from_url(url)?;
    Ok(Pool::new(opts)?)
}

fn get_user(user: &mut DovecotUser, pool: &Pool, user_query: &str) -> AuthResult<()> {
    if user.user.is_empty() {
        return Err(Error::NoUser);
    }

    let mut conn = pool.get_conn()?;
    let stmt = conn.prep(user_query)?;

    match conn.exec_first(&stmt, params! { "username" => &user.user })? {
        Some(res) => {
            let row: Row = res;
            for column in row.columns_ref() {
                let column_name = column.name_str();
                let value = match column_name.as_ref() {
                    "uid"|"gid" => from_value_opt::<i64>(row[column_name.as_ref()].clone())?.to_string(),
                    _ => from_value_opt::<String>(row[column_name.as_ref()].clone())?
                };
                match column_name.as_ref() {
                    "user" => user.user = value,
                    "password" => user.password = value,
                    "home" => user.home = Some(value),
                    "mail" => user.mail = Some(value),
                    "uid" => user.uid = Some(value),
                    "gid" => user.gid = Some(value),
                    "quota_rule" => user.quota_rule = Some(value),
                    _ => ()
                };
            }
            Ok(())
        },
        None => Err(Error::NoUser)
    }
}

pub fn update_password(username: &str, password: &str, pool: &Pool, update_query: &str) -> AuthResult<()> {
    let mut conn = pool.get_conn()?;
    let stmt = conn.prep(update_query)?;
    Ok(conn.exec_drop(&stmt, params! { "username" => username, "password" => password })?)
}

pub fn get_hashes(username: &str, pool: &Pool, cache_table: &str, max_lifetime: i64) -> AuthResult<Vec<(String, i64)>> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        concat!("SELECT password, UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) AS last_verified FROM {} ",
                "WHERE username = :username AND UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) <= :max_lifetime ORDER BY last_verified"),
        cache_table);
    let stmt = conn.prep(statement)?;
    let hash_list: Vec<(String, i64)> = conn.exec_map(&stmt, params! { "username" => username, "max_lifetime" => max_lifetime },
                                                      |row: Row| ( from_value(row["password"].clone()), from_value(row["last_verified"].clone()) ))?;
    Ok(hash_list)
}

pub fn save_hash(username: &str, password: &str, pool: &Pool, cache_table: &str) -> AuthResult<()> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        concat!("INSERT INTO {} (username, password, last_verified) ",
                "VALUES (:username, :password, NOW()) ON DUPLICATE KEY UPDATE last_verified = NOW()"),
        cache_table);
    let stmt = conn.prep(statement)?;
    Ok(conn.exec_drop(&stmt, params! { "username" => username, "password" => password })?)
}

pub fn delete_hash(username: &str, password: &str, pool: &Pool, cache_table: &str) -> AuthResult<()> {
    let mut conn = pool.get_conn()?;
    let statement = format!("DELETE FROM {} WHERE username = :username AND password = :password", cache_table);
    let stmt = conn.prep(statement)?;
    Ok(conn.exec_drop(&stmt, params! { "username" => username, "password" => password })?)
}

pub fn delete_dead_hashes(max_lifetime: i64, pool: &Pool, cache_table: &str) -> AuthResult<()> {
    let mut conn = pool.get_conn()?;
    let statement = format!("DELETE FROM {} WHERE UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) > :max_lifetime", cache_table);
    let stmt = conn.prep(statement)?;
    Ok(conn.exec_drop(&stmt, params! { "max_lifetime" => max_lifetime })?)
}



#[derive(Debug, Clone, Deserialize)]
pub struct DBLookupConfig {
    pub user_query: String,
}

#[derive(Debug, Clone)]
pub struct DBLookupModule<'a> {
    config: DBLookupConfig,
    conn_pool: &'a Pool,
}

impl<'a> DBLookupModule<'a> {
    pub fn new(config: DBLookupConfig, conn_pool: &'a Pool) -> Self {
        Self { config, conn_pool }
    }
}

impl CredentialsLookup for DBLookupModule<'_> {
    fn credentials_lookup(&self, user: &mut DovecotUser) -> AuthResult<()> {
        get_user(user, self.conn_pool, &self.config.user_query)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DBCacheVerifyConfig {
    pub db_table: String,
    pub verify_interval: i64,
    pub max_lifetime: i64,
    pub cleanup: bool,
    pub hash_scheme: Option<hashlib::Scheme>,
    pub allow_expired_on_error: bool,
}

#[derive(Debug, Clone)]
pub struct DBCacheVerifyModule<'a, M: CredentialsVerify> {
    config: DBCacheVerifyConfig,
    conn_pool: &'a Pool,
    module: M,
    hash_scheme: hashlib::Scheme,
}

impl<'a, M: CredentialsVerify> DBCacheVerifyModule<'a, M> {
    pub fn new(config: DBCacheVerifyConfig, conn_pool: &'a Pool, module: M) -> Self {
        let hash_scheme = config.hash_scheme.as_ref().cloned().unwrap_or(hashlib::Scheme::SSHA512);
        Self { config, conn_pool, module, hash_scheme }
    }
}

impl<M: CredentialsVerify> CredentialsVerify for DBCacheVerifyModule<'_, M> {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<bool> {
        if self.config.cleanup {
            delete_dead_hashes(self.config.max_lifetime, self.conn_pool, &self.config.db_table)?;
        }
        let mut verified_hashes: Vec<String> = Vec::new();
        let mut expired_hashes: Vec<String> = Vec::new();
        for (hash, last_verify) in get_hashes(&user.user, self.conn_pool, &self.config.db_table, self.config.max_lifetime)? {
            if last_verify <= self.config.verify_interval {
                verified_hashes.push(hash);
            } else if last_verify <= self.config.max_lifetime {
                expired_hashes.push(hash);
            }
        }

        if hashlib::get_matching_hash(password, &verified_hashes).is_some() {
            return Ok(true)
        }

        match self.module.credentials_verify(user, password) {
            Ok(verify_ok) => {
                if verify_ok {
                    let hash = hashlib::get_matching_hash(password, &expired_hashes)
                        .unwrap_or(hashlib::hash(password, &self.hash_scheme));
                    save_hash(&user.user, &hash, self.conn_pool, &self.config.db_table)?;
                    Ok(true)
                } else {
                    let invalid_hash = hashlib::get_matching_hash(password, &expired_hashes);
                    if let Some(hash) = invalid_hash {
                        delete_hash(&user.user, &hash, self.conn_pool, &self.config.db_table)?;
                    }
                    Err(Error::PermFail)
                }
            },
            Err(err) => {
                eprintln!("{}", err);
                if !self.config.allow_expired_on_error {
                    return Err(Error::PermFail);
                }
                match hashlib::get_matching_hash(password, &expired_hashes) {
                    Some(_) => {
                        Ok(true)
                    },
                    None => {
                        Err(Error::PermFail)
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DBUpdateCredentialsConfig {
    pub update_password_query: String,
    pub hash_scheme: hashlib::Scheme,
    pub target_hash_scheme: hashlib::Scheme,
}

#[derive(Debug, Clone)]
pub struct DBUpdateCredentialsModule<'a> {
    config: DBUpdateCredentialsConfig,
    conn_pool: &'a Pool
}

impl<'a> DBUpdateCredentialsModule<'a> {
    pub fn new(config: DBUpdateCredentialsConfig, conn_pool: &'a Pool) -> Self {
        Self { config, conn_pool }
    }
}

impl CredentialsUpdate for DBUpdateCredentialsModule<'_> {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        if !user.password.is_empty() && !self.config.update_password_query.is_empty() {
            let hash_prefix: String = format!("{{{}}}", &self.config.hash_scheme.as_str());
            if user.password.starts_with(&hash_prefix) && hashlib::verify_hash(&password, &user.password) {
                let hash = hashlib::hash(&password, &self.config.target_hash_scheme);
                update_password(&user.user, &hash, &self.conn_pool, &self.config.update_password_query)?;
            }
        }
        Ok(())
    }
}