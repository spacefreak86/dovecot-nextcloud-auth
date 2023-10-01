// dovecot-auth is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// dovecot-auth is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with dovecot-auth.  If not, see <http://www.gnu.org/licenses/>.

use crate::{
    hashlib, AuthError, AuthResult, CredentialsLookup, CredentialsUpdate, CredentialsVerify,
    CredentialsVerifyCache, DovecotUser, InternalVerifyModule,
};

use mysql::prelude::*;
use mysql::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

impl From<mysql::Error> for AuthError {
    fn from(error: mysql::Error) -> Self {
        AuthError::TempFail(error.to_string())
    }
}

pub fn get_conn_pool(url: &str) -> Result<Pool, mysql::Error> {
    let opts = Opts::from_url(url)?;
    Ok(Pool::new(opts)?)
}

fn get_user(user: &mut DovecotUser, pool: &Pool, user_query: &str) -> Result<bool> {
    if user.user.is_empty() {
        return Ok(false);
    }

    let mut conn = pool.get_conn()?;
    let stmt = conn.prep(user_query)?;

    match conn.exec_first::<Row, _, _>(&stmt, params! { "username" => &user.user })? {
        Some(row) => {
            let mut got_any_value = false;
            for column in row.columns_ref() {
                let column_name = column.name_str();
                let value = match column_name.as_ref() {
                    "uid" | "gid" => {
                        from_value_opt::<u64>(row[column_name.as_ref()].clone())?.to_string()
                    }
                    _ => from_value_opt::<String>(row[column_name.as_ref()].clone())?,
                };
                if !value.is_empty() {
                    let mut got_value = true;
                    match column_name.as_ref() {
                        "user" => user.user = value,
                        "password" => user.password = value,
                        "home" => user.home = Some(value),
                        "mail" => user.mail = Some(value),
                        "uid" => user.uid = Some(value),
                        "gid" => user.gid = Some(value),
                        "quota_rule" => user.quota_rule = Some(value),
                        _ => got_value = false,
                    }
                    if got_value {
                        got_any_value = true;
                    }
                };
            }
            Ok(got_any_value)
        }
        None => Ok(false),
    }
}

fn update_password(username: &str, password: &str, pool: &Pool, update_query: &str) -> Result<()> {
    let mut conn = pool.get_conn()?;
    let stmt = conn.prep(update_query)?;
    Ok(conn.exec_drop(
        &stmt,
        params! { "username" => username, "password" => password },
    )?)
}

fn get_hashes(
    username: &str,
    pool: &Pool,
    cache_table: &str,
    max_lifetime: u64,
) -> Result<Vec<(String, u64)>> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        concat!("SELECT password, UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) AS last_verified FROM {} ",
                "WHERE username = :username AND UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) <= :max_lifetime ORDER BY last_verified"),
        cache_table);
    let stmt = conn.prep(statement)?;
    let hash_list: Vec<(String, u64)> = conn.exec_map(
        &stmt,
        params! { "username" => username, "max_lifetime" => max_lifetime },
        |row: Row| {
            (
                from_value(row["password"].clone()),
                from_value(row["last_verified"].clone()),
            )
        },
    )?;
    Ok(hash_list)
}

fn save_hash(username: &str, password: &str, pool: &Pool, cache_table: &str) -> Result<()> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        concat!(
            "INSERT INTO {} (username, password, last_verified) ",
            "VALUES (:username, :password, NOW()) ON DUPLICATE KEY UPDATE last_verified = NOW()"
        ),
        cache_table
    );
    let stmt = conn.prep(statement)?;
    Ok(conn.exec_drop(
        &stmt,
        params! { "username" => username, "password" => password },
    )?)
}

fn delete_hash(username: &str, password: &str, pool: &Pool, cache_table: &str) -> Result<()> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        "DELETE FROM {} WHERE username = :username AND password = :password",
        cache_table
    );
    let stmt = conn.prep(statement)?;
    Ok(conn.exec_drop(
        &stmt,
        params! { "username" => username, "password" => password },
    )?)
}

fn delete_dead_hashes(max_lifetime: u64, pool: &Pool, cache_table: &str) -> Result<()> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        "DELETE FROM {} WHERE UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) > :max_lifetime",
        cache_table
    );
    let stmt = conn.prep(statement)?;
    Ok(conn.exec_drop(&stmt, params! { "max_lifetime" => max_lifetime })?)
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DBLookupConfig {
    pub user_query: String,
}

impl Default for DBLookupConfig {
    fn default() -> Self {
        Self { user_query: String::from(
            concat!("SELECT maildir AS home, CONCAT('maildir:', maildir) as mail, uid, gid, CONCAT('*:bytes=', quota) AS quota_rule, password FROM mailbox ",
                    "WHERE username = :username AND active = '1'"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct DBLookupModule {
    config: DBLookupConfig,
    conn_pool: Pool,
}

impl DBLookupModule {
    pub fn new(config: DBLookupConfig, conn_pool: Pool) -> Self {
        Self { config, conn_pool }
    }
}

impl CredentialsLookup for DBLookupModule {
    fn credentials_lookup(&mut self, user: &mut DovecotUser) -> AuthResult<bool> {
        Ok(get_user(user, &self.conn_pool, &self.config.user_query)?)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DBCacheVerifyConfig {
    pub db_table: String,
    pub verify_interval: u64,
    pub max_lifetime: u64,
    pub cleanup: bool,
    pub hash_scheme: Option<hashlib::Scheme>,
    pub allow_expired_on_error: bool,
}

impl Default for DBCacheVerifyConfig {
    fn default() -> Self {
        Self {
            db_table: String::from("password_cache"),
            verify_interval: 60,
            max_lifetime: 86400,
            cleanup: true,
            hash_scheme: Some(hashlib::Scheme::SSHA512),
            allow_expired_on_error: false,
        }
    }
}

pub struct DBCacheVerifyModule {
    config: DBCacheVerifyConfig,
    conn_pool: Pool,
    module: Box<dyn CredentialsVerify>,
    hash_scheme: hashlib::Scheme,
}

impl DBCacheVerifyModule {
    pub fn new(
        config: DBCacheVerifyConfig,
        conn_pool: Pool,
        module: Box<dyn CredentialsVerify>,
    ) -> Self {
        let hash_scheme = config
            .hash_scheme
            .as_ref()
            .cloned()
            .unwrap_or(hashlib::Scheme::SSHA512);
        Self {
            config,
            conn_pool,
            module,
            hash_scheme,
        }
    }
}

impl CredentialsVerifyCache for DBCacheVerifyModule {
    fn hash(&self, password: &str) -> String {
        hashlib::hash(password, &self.hash_scheme)
    }

    fn get_hashes(&self, user: &str) -> AuthResult<(Vec<String>, Vec<String>)> {
        let hashes = get_hashes(
            user,
            &self.conn_pool,
            &self.config.db_table,
            self.config.max_lifetime,
        )?;

        let mut verified_hashes: Vec<String> = Vec::new();
        let mut expired_hashes: Vec<String> = Vec::new();

        for (hash, last_verify) in hashes {
            if last_verify <= self.config.verify_interval {
                verified_hashes.push(hash);
            } else if last_verify <= self.config.max_lifetime {
                expired_hashes.push(hash);
            }
        }
        Ok((verified_hashes, expired_hashes))
    }

    fn insert(&mut self, user: &str, hash: &str) -> AuthResult<()> {
        Ok(save_hash(
            user,
            hash,
            &self.conn_pool,
            &self.config.db_table,
        )?)
    }

    fn delete(&mut self, user: &str, hash: &str) -> AuthResult<()> {
        Ok(delete_hash(
            user,
            hash,
            &self.conn_pool,
            &self.config.db_table,
        )?)
    }

    fn cleanup(&mut self) -> AuthResult<()> {
        if self.config.cleanup {
            delete_dead_hashes(
                self.config.max_lifetime,
                &self.conn_pool,
                &self.config.db_table,
            )?;
        }
        Ok(())
    }

    fn save(&self) -> AuthResult<()> {
        Ok(())
    }

    fn module(&mut self) -> &mut Box<dyn CredentialsVerify> {
        &mut self.module
    }

    fn allow_expired_on_error(&self) -> bool {
        self.config.allow_expired_on_error
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DBUpdateCredentialsConfig {
    pub update_password_query: String,
    pub hash_scheme: hashlib::Scheme,
}

impl Default for DBUpdateCredentialsConfig {
    fn default() -> Self {
        Self {
            update_password_query: String::from(
                "UPDATE mailbox SET password = :password WHERE username = :username",
            ),
            hash_scheme: hashlib::Scheme::SSHA512,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DBUpdateCredentialsModule {
    config: DBUpdateCredentialsConfig,
    conn_pool: Pool,
}

impl DBUpdateCredentialsModule {
    pub fn new(config: DBUpdateCredentialsConfig, conn_pool: Pool) -> Self {
        Self { config, conn_pool }
    }
}

impl CredentialsUpdate for DBUpdateCredentialsModule {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        if !self.config.update_password_query.is_empty() {
            let hash_prefix: String = format!("{{{}}}", &self.config.hash_scheme.as_str());
            if user.password.starts_with(&hash_prefix) {
                return Ok(());
            }

            match InternalVerifyModule::new().credentials_verify(user, password) {
                Ok(true) => {
                    let hash = hashlib::hash(password, &self.config.hash_scheme);
                    update_password(
                        &user.user,
                        &hash,
                        &self.conn_pool,
                        &self.config.update_password_query,
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}
