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
use dovecot_auth::db::*;

use dovecot_auth::file::{BinaryCacheFile, FileCacheVerifyModule};

#[cfg(feature = "http")]
use dovecot_auth::http::*;

use dovecot_auth::{authenticate, AuthError, AuthResult, ReplyBin, DOVECOT_TEMPFAIL};
use dovecot_auth::{
    CredentialsLookup, CredentialsVerify, InternalVerifyModule, LookupModule, PostLookup,
    PostLookupModule, VerifyCacheModule, VerifyModule,
};

use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::time::SystemTime;

const MYNAME: &'static str = clap::crate_name!();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    configured: bool,
    #[cfg(feature = "db")]
    db_url: Option<String>,
    lookup_module: Option<LookupModule>,
    post_lookup_module: Option<PostLookupModule>,
    verify_module: Option<VerifyModule>,
    verify_cache_module: Option<VerifyCacheModule>,
    allow_internal_verify_hosts: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        #[cfg(feature = "db")]
        let lookup_module = Some(LookupModule::DB(DBLookupConfig::default()));
        #[cfg(not(feature = "db"))]
        let lookup_module: Option<LookupModule> = None;

        #[cfg(feature = "db")]
        let post_lookup_module = Some(PostLookupModule::DBUpdateCredentials(
            DBUpdateCredentialsConfig::default(),
        ));
        #[cfg(not(feature = "db"))]
        let post_lookup_module: Option<PostLookupModule> = None;

        #[cfg(feature = "http")]
        let verify_module = Some(VerifyModule::Http(HttpVerifyConfig::default()));
        #[cfg(not(feature = "http"))]
        let verify_module: Option<VerifyModule> = Some(VerifyModule::Internal);

        #[cfg(feature = "db")]
        let verify_cache_module = Some(VerifyCacheModule::DB(DBCacheVerifyConfig::default()));
        #[cfg(not(feature = "db"))]
        let verify_cache_module: Option<VerifyCacheModule> =
            Some(VerifyCacheModule::File(FileCacheVerifyConfig::default()));

        Self {
            configured: false,
            #[cfg(feature = "db")]
            db_url: Some(String::from("mysql://DBUSER:DBPASS@localhost:3306/postfix")),
            lookup_module,
            post_lookup_module,
            verify_module,
            verify_cache_module,
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
    #[arg(short, long, default_value_t = false, help = "print example config")]
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
    debug!("parse config file {:?}", config_file);
    config_file.read_to_string(&mut content)?;
    let config: Config = toml::from_str(&content)?;
    if let Some(file) = cache_file {
        debug!("save config to cache file {:?}", file);
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
    let mut opt_cache_file = cache_path
        .as_ref()
        .map(|path| File::options().read(true).write(true).open(path).ok())
        .flatten();

    let config = match opt_cache_file.take() {
        Some(cache_file) => {
            debug!("got config cache file {:?}, determining age", cache_file);
            let cache_modified = get_modified(&cache_file).unwrap_or(SystemTime::UNIX_EPOCH);
            let config_modified = get_modified(&config_file).unwrap_or(SystemTime::now());
            debug!("config file last modified: {:?}", config_modified);
            debug!("cache file last modified: {:?}", cache_modified);
            match config_modified.duration_since(cache_modified) {
                Ok(duration) => {
                    debug!(
                        "cache file is {} older thand conf file, refresh",
                        duration.as_secs()
                    );
                    parse_config_file(config_file, Some(cache_file))?
                }
                Err(_) => match Config::load_from_file(&cache_file) {
                    Ok(config) => config,
                    Err(err) => {
                        debug!("unable to load config cache file: {err}");
                        parse_config_file(config_file, Some(cache_file))?
                    }
                },
            }
        }
        None => {
            let cache_file = match cache_path {
                Some(path) => match File::create(path) {
                    Ok(file) => Some(file),
                    Err(err) => {
                        warn!("unable to create config cache file: {err}");
                        None
                    }
                },
                None => None,
            };
            parse_config_file(config_file, cache_file)?
        }
    };
    Ok(config)
}

fn main() {
    let binary_name = env::current_exe()
        .ok()
        .and_then(|e| e.file_name().and_then(|n| n.to_str().map(|s| s.to_owned())))
        .unwrap_or(String::from(MYNAME));

    let args = Args::parse();

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(args.verbose.log_level_filter())
        .init();

    if args.print_example_config {
        print_example_config();
        std::process::exit(0);
    }

    let path = env::var("DOVECOT_AUTH_CONFIG").unwrap_or(format!("/etc/{binary_name}.toml"));
    let cache_path = env::var("DOVECOT_AUTH_CONFIG_CACHE").ok();

    let config = read_config_file(&path, cache_path).unwrap_or_else(|err| {
        error!("config file: {path}: {err}");
        std::process::exit(err.exit_code());
    });

    if !config.configured {
        error!("{MYNAME} is not configured");
        std::process::exit(DOVECOT_TEMPFAIL);
    }

    let mut fd = None;

    if args.test {
        // in test mode, read credentials from fd 0 (stdin)
        fd = Some(0);
    }

    let reply_bin =
        ReplyBin::new(args.reply_bin, args.args.unwrap_or_default()).unwrap_or_else(|err| {
            error!("argument error: {err}");
            std::process::exit(DOVECOT_TEMPFAIL);
        });

    #[cfg(feature = "db")]
    let conn_pool = config.db_url.as_ref().map(|url| {
        get_conn_pool(url).unwrap_or_else(|err| {
            error!("database error: {err}");
            std::process::exit(DOVECOT_TEMPFAIL);
        })
    });

    let mut lookup_module: Option<Box<dyn CredentialsLookup>> = None;
    if let Some(module) = config.lookup_module {
        match module {
            #[cfg(feature = "db")]
            LookupModule::DB(config) => {
                match conn_pool.as_ref().cloned() {
                    Some(pool) => {
                        lookup_module = Some(Box::new(DBLookupModule::new(config, pool)));
                    }
                    None => {
                        error!("config option db_url not set (needed by lookup_module)");
                        std::process::exit(DOVECOT_TEMPFAIL);
                    }
                };
            }
        };
    };

    let mut post_lookup_module: Option<Box<dyn PostLookup>> = None;
    if let Some(module) = config.post_lookup_module {
        match module {
            #[cfg(feature = "db")]
            PostLookupModule::DBUpdateCredentials(config) => match conn_pool.as_ref().cloned() {
                Some(pool) => {
                    post_lookup_module =
                        Some(Box::new(DBUpdateCredentialsModule::new(config, pool)));
                }
                None => {
                    error!("config option db_url not set (needed by update_credentials_module)");
                    std::process::exit(DOVECOT_TEMPFAIL);
                }
            },
        };
    };

    let mut verify_module: Option<Box<dyn CredentialsVerify>> = None;
    if let Some(module) = config.verify_module {
        match module {
            #[cfg(feature = "http")]
            VerifyModule::Http(config) => {
                verify_module = Some(Box::new(HttpVerifyModule::new(config)));
            }
            VerifyModule::Internal => {
                verify_module = Some(Box::new(InternalVerifyModule::new()));
            }
        };
    };

    if let Some(module) = config.verify_cache_module {
        if let Some(vrfy_mod) = verify_module {
            match module {
                #[cfg(feature = "db")]
                VerifyCacheModule::DB(config) => match conn_pool.as_ref().cloned() {
                    Some(pool) => {
                        verify_module =
                            Some(Box::new(DBCacheVerifyModule::new(config, pool, vrfy_mod)));
                    }
                    None => {
                        error!("config option db_url not set (needed by verify_cache_module)");
                        std::process::exit(DOVECOT_TEMPFAIL);
                    }
                },
                VerifyCacheModule::File(config) => {
                    verify_module = Some(Box::new(FileCacheVerifyModule::new(config, vrfy_mod)));
                }
            };
        }
    };

    let rc = match authenticate(
        lookup_module,
        post_lookup_module,
        verify_module,
        config.allow_internal_verify_hosts,
        reply_bin,
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

#[cfg(test)]
mod tests {
    use crate::Config;
    use bincode;

    #[test]
    fn config_bincode_serde() {
        let config = Config::default();
        let data = bincode::serialize(&config).unwrap_or_default();
        let new_config = bincode::deserialize::<Config>(&data).ok();
        assert_eq!(new_config, Some(config));
    }
}
