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

use std::default::Default;
use std::{fs::File, io::Read, os::unix::io::FromRawFd, };
use config_file::{FromConfigFile, ConfigFileError};
use serde::Deserialize;
use mysql::*;
use mysql::prelude::*;

#[derive(Deserialize)]
struct Config {
    db_url: String,
    user_query: String,
    nextcloud_url: String,
}

#[derive(Default)]
pub struct DovecotUser {
    pub username: String,
    pub db_password: String,
    pub home: String,
    pub mail: String,
    pub uid: String,
    pub gid: String,
    pub quota_rule: String,
}

impl std::ops::Index<&'_ str> for DovecotUser {
    type Output = String;
    fn index(&self, s: &str) -> &String {
        match s {
            "username" => &self.username,
            "db_password" => &self.db_password,
            "home" => &self.home,
            "mail" => &self.mail,
            "uid" => &self.uid,
            "gid" => &self.gid,
            "quota_rule" => &self.quota_rule,
            _ => panic!("unknown field: {}", s),
        }
    }
}

impl std::ops::IndexMut<&'_ str> for DovecotUser {
    fn index_mut(&mut self, s: &str) -> &mut String {
        match s {
            "username" => &mut self.username,
            "db_password" => &mut self.db_password,
            "home" => &mut self.home,
            "mail" => &mut self.mail,
            "uid" => &mut self.uid,
            "gid" => &mut self.gid,
            "quota_rule" => &mut self.quota_rule,
            _ => panic!("unknown field: {}", s),
        }
    }
}

impl std::fmt::Display for DovecotUser {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut string = String::new();
        for field in &USERDB_FIELDS {
            string.push_str(&format!("{}: {}\n", field, self[field]));
        }
        write!(f, "{}", string)
    }
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

fn mysql_value_to_string(value: &Value) -> std::result::Result<String, mysql::error::Error> {
    match from_value_opt::<String>(value.clone()) {
        Ok(s) => Ok(s),
        Err(_) => Ok(from_value_opt::<i64>(value.clone())?.to_string())
    }
}

const USERDB_FIELDS: [&str; 6] = ["password", "home", "mail", "uid", "gid", "quota_rule"];

fn user_lookup(username: &str, url: &str, user_query: &str) -> std::result::Result<Option<DovecotUser>, mysql::error::Error> {
    let opts = Opts::from_url(url)?;
    let pool = Pool::new(opts)?;
    let mut conn = pool.get_conn()?;
    let stmt = conn.prep(user_query)?;
    match conn.exec_first(&stmt, params! { username })? {
        Some(result) => {
            let row: Row = result;
            let mut query_result: Vec<(String, String)> = Vec::new();

            for column in row.columns_ref() {
                let column_name = column.name_str();
                let column_name_str = column_name.to_string();

                if !USERDB_FIELDS.contains(&&column_name_str[..]) {
                    continue;
                }

                let value = mysql_value_to_string(&row[column_name.as_ref()])?;
                query_result.push((column_name_str, value));
            }

            let mut user = DovecotUser { username: username.to_string().to_lowercase(), ..Default::default() };
            for (field, value) in query_result {
                user[&field] = value;
            }
            Ok(Some(user))
        },
        None => Ok(None)
    }
}

pub fn nextcloud_auth(fd: i32, config_file: &str) -> std::result::Result<DovecotUser, AuthError> {
    let config = Config::from_config_file(config_file)?;
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut input = String::new();
    f.read_to_string(&mut input)?;
    let credentials: Vec<&str> = input.split("\0").collect();

    if credentials.len() >= 2 {
        match user_lookup(credentials[0], &config.db_url, &config.user_query)? {
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
