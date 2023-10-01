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

use dovecot_auth::modules::file::{BinaryCacheFile, FileCacheVerifyConfig, FileCacheVerifyModule};
#[cfg(feature = "http")]
use dovecot_auth::modules::http::*;

use dovecot_auth::modules::{
    CredentialsLookup, CredentialsUpdate, CredentialsVerify, InternalVerifyModule,
};
use dovecot_auth::{authenticate, AuthError, AuthResult, ReplyBin, RC_TEMPFAIL};

use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::time::SystemTime;
use log::{error, info, warn};

const MYNAME: &str = clap::crate_name!();
const DEFAULT_CONFIG_CACHE_FILE: &str = "/tmp/dovecot-auth-config.cache";

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
    File(FileCacheVerifyConfig),
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
    config_cache_file: Option<String>,
    #[cfg(feature = "db")]
    db_url: Option<String>,
    lookup_module: Option<LookupModule>,
    verify_module: Option<VerifyModule>,
    verify_cache_module: Option<VerifyCacheModule>,
    update_credentials_module: Option<UpdateCredentialsModule>,
    allow_internal_verify_hosts: Option<Vec<String>>,
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
        let verify_cache_module: Option<VerifyCacheModule> =
            Some(VerifyCacheModule::File(FileCacheVerifyConfig::default()));

        #[cfg(feature = "db")]
        let update_credentials_module = Some(UpdateCredentialsModule::DB(
            DBUpdateCredentialsConfig::default(),
        ));
        #[cfg(not(feature = "db"))]
        let update_credentials_module: Option<UpdateCredentialsModule> = None;

        Self {
            configured: false,
            config_cache_file: Some(String::from(DEFAULT_CONFIG_CACHE_FILE)),
            #[cfg(feature = "db")]
            db_url: Some(String::from("mysql://DBUSER:DBPASS@localhost:3306/postfix")),
            lookup_module,
            verify_module,
            verify_cache_module,
            update_credentials_module,
            allow_internal_verify_hosts: Some(vec![]),
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
/// CheckPassword binary for Dovecot
///
/// https://doc.dovecot.org/configuration_manual/authentication/checkpassword/
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
    #[command(flatten)]
    verbose: Verbosity<WarnLevel>,
    #[arg(trailing_var_arg = true)]
    args: Option<Vec<String>>,
}

fn parse_config_file(mut config_file: File, cache_file: Option<File>) -> AuthResult<Config> {
    let mut content = String::new();
    config_file.read_to_string(&mut content)?;
    let config: Config = toml::from_str(&content)?;
    if let Some(file) = cache_file {
        config.save_to_file(file).unwrap_or_else(|err| {
            warn!("unable to write config cache file: {err}");
        });
    }
    Ok(config)
}

fn get_modified(file: &File) -> AuthResult<SystemTime> {
    Ok(file.metadata()?.modified()?)
}

fn read_config_file<P, C>(config_path: P, cache_path: Option<C>) -> AuthResult<Config>
where
    P: AsRef<Path>,
    C: AsRef<Path>,
{
    let config_file = File::open(config_path)?;
    let mut opt_cache_file = cache_path.map(|path| File::open(path).ok()).flatten();

    let config = match opt_cache_file.take() {
        Some(cache_file) => {
            let cache_modified = get_modified(&cache_file).unwrap_or(SystemTime::UNIX_EPOCH);
            let config_modified = get_modified(&config_file).unwrap_or(SystemTime::now());
            match config_modified.duration_since(cache_modified) {
                Ok(_) => parse_config_file(config_file, opt_cache_file)?,
                Err(_) => Config::load_from_file(cache_file)
                    .unwrap_or(parse_config_file(config_file, opt_cache_file)?),
            }
        }
        None => parse_config_file(config_file, opt_cache_file)?,
    };
    Ok(config)
}

fn main() {
    let args = Args::parse();

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(args.verbose.log_level_filter())
        .init();

    if args.print_example_config {
        print_example_config();
        std::process::exit(0);
    }

    let path = env::var("DOVECOT_AUTH_CONFIG").unwrap_or(format!("/etc/dovecot/{MYNAME}.toml"));
    let cache_path = env::var("DOVECOT_AUTH_CONFIG_CACHE").ok();

    let config = read_config_file(&path, cache_path).unwrap_or_else(|err| {
        error!("config file: {path}: {err}");
        std::process::exit(err.exit_code());
    });

    if !config.configured {
        error!("{MYNAME} is not configured");
        std::process::exit(RC_TEMPFAIL);
    }

    let mut fd = None;

    if args.test {
        // in test mode, read credentials from fd 0 (stdin)
        fd = Some(0);
    }

    let reply_bin =
        ReplyBin::new(args.reply_bin, args.args.unwrap_or_default()).unwrap_or_else(|err| {
            error!("argument error: {err}");
            std::process::exit(RC_TEMPFAIL);
        });

    #[cfg(feature = "db")]
    let conn_pool = config.db_url.as_ref().map(|url| {
        get_conn_pool(url).unwrap_or_else(|err| {
            error!("unable to parse db_url: {err}");
            std::process::exit(RC_TEMPFAIL);
        })
    });

    let mut lookup_mod: Option<Box<dyn CredentialsLookup>> = None;
    if let Some(module) = config.lookup_module {
        match module {
            #[cfg(feature = "db")]
            LookupModule::DB(config) => {
                match conn_pool.as_ref().cloned() {
                    Some(pool) => {
                        lookup_mod = Some(Box::new(DBLookupModule::new(config, pool)));
                    }
                    None => {
                        error!("config option db_url not set (needed by lookup_module)");
                        std::process::exit(RC_TEMPFAIL);
                    }
                };
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
                VerifyCacheModule::DB(config) => match conn_pool.as_ref().cloned() {
                    Some(pool) => {
                        verify_mod =
                            Some(Box::new(DBCacheVerifyModule::new(config, pool, vrfy_mod)));
                    }
                    None => {
                        error!("config option db_url not set (needed by verify_cache_module)");
                        std::process::exit(RC_TEMPFAIL);
                    }
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
            UpdateCredentialsModule::DB(config) => match conn_pool.as_ref().cloned() {
                Some(pool) => {
                    update_mod = Some(Box::new(DBUpdateCredentialsModule::new(config, pool)));
                }
                None => {
                    error!("config option db_url not set (needed by update_credentials_module)");
                    std::process::exit(RC_TEMPFAIL);
                }
            },
        };
    };

    let rc = match authenticate(
        &mut lookup_mod,
        &mut verify_mod,
        &update_mod,
        &config.allow_internal_verify_hosts,
        &reply_bin,
        fd,
    ) {
        Ok(_) => 0,
        Err(err) => {
            match &err {
                AuthError::PermFail | AuthError::NoUser => {
                    info!("{err}");
                }
                AuthError::TempFail(msg) => {
                    warn!("{msg}");
                }
            }
            err.exit_code()
        }
    };

    std::process::exit(rc);
}
