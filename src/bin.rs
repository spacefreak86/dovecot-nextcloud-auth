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

#[cfg(feature = "db")]
use dovecot_auth::modules::db::*;

use dovecot_auth::modules::file::{FileCacheVerifyConfig, FileCacheVerifyModule};
#[cfg(feature = "http")]
use dovecot_auth::modules::http::*;

use dovecot_auth::modules::{
    CredentialsLookup, CredentialsUpdate, CredentialsVerify, InternalVerifyModule,
};
use dovecot_auth::{authenticate, AuthResult, Error, ReplyBin, RC_TEMPFAIL};

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::read_to_string;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LookupModule {
    #[cfg(feature = "db")]
    DB(DBLookupConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VerifyModule {
    Internal,
    #[cfg(feature = "http")]
    Http(HttpVerifyConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VerifyCacheModule {
    #[cfg(feature = "db")]
    DB(DBCacheVerifyConfig),
    File(FileCacheVerifyConfig)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UpdateCredentialsModule {
    #[cfg(feature = "db")]
    DB(DBUpdateCredentialsConfig),
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
        #[cfg(feature = "db")]
        let lookup_module = Some(LookupModule::DB(DBLookupConfig::default()));
        #[cfg(not(feature = "db"))]
        let lookup_module: Option<LookupModule> = None;

        #[cfg(feature = "http")]
        let verify_module = Some(VerifyModule::Http(HttpVerifyConfig::default()));
        #[cfg(not(feature = "http"))]
        let verify_module: Option<VerifyModule> = Some(VerifyModule::Internal);

        #[cfg(feature = "db")]
        let verify_cache_module = Some(VerifyCacheModule::DB(DBCacheVerifyConfig::default()));
        #[cfg(not(feature = "db"))]
        let verify_cache_module: Option<VerifyCacheModule> = Some(VerifyCacheModule::File(FileCacheVerifyConfig::default()));

        #[cfg(feature = "db")]
        let update_credentials_module = Some(UpdateCredentialsModule::DB(DBUpdateCredentialsConfig::default(),
        ));
        #[cfg(not(feature = "db"))]
        let update_credentials_module: Option<UpdateCredentialsModule> = None;

        Self {
            configured: false,
            #[cfg(feature = "db")]
            db_url: String::from("mysql://DBUSER:DBPASS@localhost:3306/postfix"),
            lookup_module,
            verify_module,
            verify_cache_module,
            update_credentials_module,
        }
    }
}

fn print_example_config() {
    let config = Config::default();
    let toml = toml::to_string_pretty(&config).expect("that we can render the default config");
    println!("{toml}");
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "read credentials from stdin instead of file descriptor 3"
    )]
    test: bool,
    #[arg(short, default_value_t = false, help = "print example config")]
    print_example_config: bool,
    #[arg(default_value_t = String::from("/bin/true"))]
    reply_bin: String,
    #[arg(trailing_var_arg = true)]
    args: Option<Vec<String>>,
}

fn parse_config_file<P: AsRef<Path>>(path: P) -> AuthResult<Config> {
    let content = read_to_string(&path)?;
    Ok(toml::from_str(&content)?)
}

fn main() {
    let args = Args::parse();
    let myname = clap::crate_name!();

    if args.print_example_config {
        print_example_config();
        std::process::exit(0);
    }

    let path = format!("{myname}.toml");
    let config = parse_config_file(&path).unwrap_or_else(|err| {
        eprintln!("unable to read config file: {err}");
        std::process::exit(err.exit_code());
    });

    if !config.configured {
        eprintln!("{myname} is not configured");
        std::process::exit(RC_TEMPFAIL);
    }

    let mut fd = None;

    if args.test {
        // in test mode, read credentials from fd 0 (stdin)
        fd = Some(0);
    }

    let reply_bin =
        ReplyBin::new(args.reply_bin, args.args.unwrap_or_default()).unwrap_or_else(|err| {
            eprintln!("argument error: {err}");
            std::process::exit(RC_TEMPFAIL);
        });

    #[cfg(feature = "db")]
    let conn_pool = get_conn_pool(&config.db_url).unwrap();

    let mut lookup_mod: Option<Box<dyn CredentialsLookup>> = None;
    if let Some(module) = config.lookup_module {
        match module {
            #[cfg(feature = "db")]
            LookupModule::DB(config) => {
                lookup_mod = Some(Box::new(DBLookupModule::new(config, conn_pool.clone())));
            }
        };
    };

    let mut verify_mod: Option<Box<dyn CredentialsVerify>> = None;
    if let Some(module) = config.verify_module {
        match module {
            #[cfg(feature = "http")]
            VerifyModule::Http(config) => {
                verify_mod = Some(Box::new(HttpVerifyModule::new(config)));
            }
            VerifyModule::Internal => {
                verify_mod = Some(Box::new(InternalVerifyModule {}));
            }
        };
    };

    if let Some(module) = config.verify_cache_module {
        if let Some(vrfy_mod) = verify_mod {
            match module {
                #[cfg(feature = "db")]
                VerifyCacheModule::DB(config) => {
                    verify_mod = Some(Box::new(DBCacheVerifyModule::new(
                        config,
                        conn_pool.clone(),
                        vrfy_mod,
                    )));
                },
                VerifyCacheModule::File(config) => {
                    verify_mod = Some(Box::new(FileCacheVerifyModule::new(config, vrfy_mod)));
                }
            };
        }
    };

    let mut update_mod: Option<Box<dyn CredentialsUpdate>> = None;
    if let Some(module) = config.update_credentials_module {
        match module {
            #[cfg(feature = "db")]
            UpdateCredentialsModule::DB(config) => {
                update_mod = Some(Box::new(DBUpdateCredentialsModule::new(config, conn_pool)));
            }
        };
    };

    let rc = match authenticate(&lookup_mod, &verify_mod, &update_mod, &reply_bin, fd) {
        Ok(_) => 0,
        Err(err) => {
            match &err {
                Error::PermFail | Error::NoUser => {
                    if args.test {
                        eprintln!("{err}");
                    }
                }
                Error::TempFail(msg) => {
                    eprintln!("{msg}");
                }
            }
            err.exit_code()
        }
    };

    std::process::exit(rc);
}
