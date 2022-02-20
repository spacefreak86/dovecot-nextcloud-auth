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

use std::collections::HashMap;
use mysql::*;
use mysql::prelude::*;

pub fn get_conn_pool(url: &str) -> std::result::Result<Pool, mysql::error::Error> {
    Ok(Pool::new(Opts::from_url(url)?)?)
}

pub fn get_user(username: &str, pool: &Pool, user_query: &str, fields: &[&str]) -> std::result::Result<Option<HashMap<String, String>>, mysql::error::Error> {
    let mut conn = pool.get_conn()?;
    let stmt = conn.prep(user_query)?;
    match conn.exec_first(&stmt, params! { "username" => username.to_lowercase() })? {
        Some(res) => {
            let row: Row = res;
            let mut user = HashMap::new();
            for column in row.columns_ref() {
                let column_name = column.name_str();
                if !fields.contains(&&column_name[..]) {
                    continue;
                } else if column_name == "uid" || column_name == "gid" {
                    user.insert(column_name.to_string(), from_value_opt::<i64>(row[column_name.as_ref()].clone())?.to_string());
                } else {
                    user.insert(column_name.to_string(), from_value_opt::<String>(row[column_name.as_ref()].clone())?);
                }
            }
            if !user.contains_key("user") {
                user.insert(String::from("user"), username.to_lowercase());
            }
            Ok(Some(user))
        },
        None => Ok(None)
    }
}

pub fn get_hashes(username: &str, pool: &Pool, cache_table: &str, max_lifetime: i64) -> std::result::Result<Vec<(String, i64)>, mysql::error::Error> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        concat!("SELECT password, UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) AS last_verified FROM {} ",
                "WHERE username = :username AND UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) <= :max_lifetime ORDER BY last_verified"),
        cache_table);
    let stmt = conn.prep(statement)?;
    let hash_list: Vec<(String, i64)> = conn.exec_map(&stmt, params! { "username" => username.to_lowercase(), "max_lifetime" => max_lifetime },
                                                      |row: Row| ( from_value(row["password"].clone()), from_value(row["last_verified"].clone()) ))?;
    Ok(hash_list)
}

pub fn save_hash(username: &str, password: &str, pool: &Pool, cache_table: &str) -> std::result::Result<(), mysql::error::Error> {
    let mut conn = pool.get_conn()?;
    let statement = format!(
        concat!("INSERT INTO {} (username, password, last_verified) ",
                "VALUES (:username, :password, NOW()) ON DUPLICATE KEY UPDATE last_verified = NOW()"),
        cache_table);
    let stmt = conn.prep(statement)?;
    conn.exec_drop(&stmt, params! { "username" => username.to_lowercase(), "password" => password })
}

pub fn delete_dead_hashes(max_lifetime: i64, pool: &Pool, cache_table: &str) -> std::result::Result<(), mysql::error::Error> {
    let mut conn = pool.get_conn()?;
    let statement = format!("DELETE FROM {} WHERE UNIX_TIMESTAMP() - UNIX_TIMESTAMP(last_verified) > :max_lifetime", cache_table);
    let stmt = conn.prep(statement)?;
    conn.exec_drop(&stmt, params! { "max_lifetime" => max_lifetime })
}
