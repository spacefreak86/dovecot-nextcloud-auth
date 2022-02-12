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

pub const USERDB_FIELDS: [&str; 6] = ["password", "home", "mail", "uid", "gid", "quota_rule"];

fn mysql_value_to_string(value: &Value) -> std::result::Result<String, mysql::error::Error> {
    match from_value_opt::<String>(value.clone()) {
        Ok(s) => Ok(s),
        Err(_) => Ok(from_value_opt::<i64>(value.clone())?.to_string())
    }
}

pub fn user_lookup(username: &str, url: &str, user_query: &str) -> std::result::Result<Option<HashMap<String, String>>, mysql::error::Error> {
    let mut conn = Pool::new(Opts::from_url(url)?)?.get_conn()?;
    let stmt = conn.prep(user_query)?;
    match conn.exec_first(&stmt, params! { username })? {
        Some(result) => {
            let row: Row = result;
            let mut user = HashMap::new();
            user.insert(String::from("username"), username.to_string().to_lowercase());
            for column in row.columns_ref() {
                let column_name = column.name_str();
                let column_name_str = column_name.to_string();

                if !USERDB_FIELDS.contains(&&column_name_str[..]) {
                    continue;
                }

                user.insert(column_name_str, mysql_value_to_string(&row[column_name.as_ref()])?);
            }
            Ok(Some(user))
        },
        None => Ok(None)
    }
}
