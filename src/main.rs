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

pub mod dovecot;

use dovecot::modules::{CredentialsLookup, CredentialsVerify, CredentialsUpdate};
use dovecot::{hashlib, ReplyBin, Error, RC_TEMPFAIL, authenticate};
use dovecot::modules::InternalVerifyModule;
use dovecot::modules::db::{DBLookupModule, DBLookupConfig, DBCacheVerifyModule, DBCacheVerifyConfig, DBUpdateCredentialsModule, DBUpdateCredentialsConfig};
use dovecot::modules::http::{HttpVerifyModule, HttpVerifyConfig};

use std::fs::{read_to_string, write};
use std::path::Path;
//use std::io::prelude::*;
use serde::{Serialize, Deserialize};


const TEST_REPLY_BIN: &str = "/bin/true";

fn help(myname: &str) {
    println!("Usage: {} [test] REPLYBIN", myname);
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LookupModule {
    DB(DBLookupConfig)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VerifyModule {
    Internal,
    Http(HttpVerifyConfig)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VerifyCacheModule {
    DB(DBCacheVerifyConfig)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UpdateCredentialsModule {
    DB(DBUpdateCredentialsConfig)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    configured: bool,
    db_url: String,
    lookup_module: Option<LookupModule>,
    verify_module: Option<VerifyModule>,
    verify_cache_module: Option<VerifyCacheModule>,
    update_credentials_module: Option<UpdateCredentialsModule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            configured: false,
            db_url: String::from("mysql://DBUSER:DBPASS@localhost:3306/postfix"),
            lookup_module: Some(LookupModule::DB(DBLookupConfig { user_query: String::from("SELECT maildir AS home, CONCAT('maildir:', maildir) as mail, uid, gid, CONCAT('*:bytes=', quota) AS quota_rule, password FROM mailbox WHERE username = :username AND active = '1'") })),
            verify_module: Some(VerifyModule::Http(HttpVerifyConfig { url: String::from("https://localhost/auth"), method: String::from("GET"), ok_code: 200, invalid_code: 403 })),
            verify_cache_module: Some(VerifyCacheModule::DB(DBCacheVerifyConfig { db_table: String::from("password_cache"), verify_interval: 60, max_lifetime: 86400, cleanup: true, hash_scheme: Some(hashlib::Scheme::SSHA512), allow_expired_on_error: false })),
            update_credentials_module: Some(UpdateCredentialsModule::DB(DBUpdateCredentialsConfig { update_password_query: String::from("UPDATE mailbox SET password = :password WHERE username = :username"), hash_scheme: hashlib::Scheme::SSHA512 }))
        }
    }
}


fn write_default_config<T: AsRef<Path>>(path: T) -> std::io::Result<()> {
    let config = toml::to_string_pretty(&Config::default())
        .expect("that we can render the default config");
    write(path, config)
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let myname = String::from("dovecot-nextcloud-auth");

    if args.len() < 2 {
        eprintln!("{myname}: missing operand");
        help(&myname);
        std::process::exit(255);
    } else if args[1] == "help" || args[1].starts_with("-h") {
        help(&myname);
        std::process::exit(0);
    }

    let path = format!("{}.toml", args.remove(0));
    let mut reply_bin = args.remove(0);
    let mut fd = None;
    let mut test = false;

    if reply_bin == "test" {
        test = true;
        // in test mode, read credentials from fd 0 (stdin)
        fd = Some(0);
        if !args.is_empty() {
            reply_bin = args.remove(0);
        } else {
            reply_bin = String::from(TEST_REPLY_BIN);
        }
    }

    let reply_bin = ReplyBin::new(reply_bin, args).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(RC_TEMPFAIL);
    });

    let config: Config = match read_to_string(&path) {
        Ok(config) => {
            match toml::from_str(&config) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("error in config file: {}", err);
                    Config::default()
                }
            }
        },
        Err(err) => {
            eprintln!("unable to read config file: {}", err);
            if let Err(err) = write_default_config(&path) {
                eprintln!("unable to write default config file: {}", err);
            }
            Config::default()
        }
    };

    if !config.configured {
        eprintln!("{} is not configured", myname);
        std::process::exit(RC_TEMPFAIL);
    }

    let conn_pool = dovecot::modules::db::get_conn_pool(&config.db_url).unwrap();

    let mut lookup_mod: Option<Box<dyn CredentialsLookup>> = None;
    if let Some(module) = config.lookup_module {
        match module {
            LookupModule::DB(config) => {
                lookup_mod = Some(Box::new(DBLookupModule::new(config, conn_pool.clone())));
            }
        };
    };

    let mut verify_mod: Option<Box<dyn CredentialsVerify>> = None;
    if let Some(module) = config.verify_module {
        match module {
            VerifyModule::Http(config) => {
                verify_mod = Some(Box::new(HttpVerifyModule::new(config)));
            },
            VerifyModule::Internal => {
                verify_mod = Some(Box::new(InternalVerifyModule{}));
            },
        };
    };

    if let Some(module) = config.verify_cache_module {
        if let Some(vrfy_mod) = verify_mod {
            match module {
                VerifyCacheModule::DB(config) => {
                    verify_mod = Some(Box::new(DBCacheVerifyModule::new(config, conn_pool.clone(), vrfy_mod)));
                },
            };
        }
    };

    let mut update_mod: Option<Box<dyn CredentialsUpdate>> = None;
    if let Some(module) = config.update_credentials_module {
        match module {
            UpdateCredentialsModule::DB(config) => {
                update_mod = Some(Box::new(DBUpdateCredentialsModule::new(config, conn_pool)));
            }
        };
    };

    let rc = match authenticate(&lookup_mod, &verify_mod, &update_mod, &reply_bin, fd) {
        Ok(_) => 0,
        Err(err) => {
            match &err {
                Error::PermFail|Error::NoUser => {
                    if test {
                        eprintln!("{}", err);
                    }
                },
                Error::TempFail(msg) => {
                    eprintln!("{}", msg);
                },
            }
            err.exit_code()
        }
    };

    std::process::exit(rc);
}
