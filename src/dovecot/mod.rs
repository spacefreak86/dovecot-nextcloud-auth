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

pub mod modules;
pub mod hashlib;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::env;
use std::ffi::{CString, NulError};
use nix::unistd::execvp;
use std::convert::Infallible;

use modules::{CredentialsLookup, CredentialsVerify, CredentialsUpdate};

pub const RC_PERMFAIL: i32 = 1;
pub const RC_NOUSER: i32 = 3;
pub const RC_TEMPFAIL: i32 = 111;

pub const INPUT_FD: i32 = 3;

#[derive(Debug, Clone)]
pub enum Error {
    PermFail,
    NoUser,
    TempFail(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::PermFail => write!(f, "invalid credentials"),
            Error::NoUser => write!(f, "user not found"),
            Error::TempFail(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PermFail => RC_PERMFAIL,
            Self::NoUser => RC_NOUSER,
            Self::TempFail(_) => RC_TEMPFAIL
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::TempFail(error.to_string())
    }
}

pub type AuthResult<T> = Result<T, Error>;

#[derive(Debug, Clone, Default)]
pub struct DovecotUser {
    pub user: String,
    pub password: String,
    pub home: Option<String>,
    pub mail: Option<String>,
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub quota_rule: Option<String>,
}

impl DovecotUser {
    pub fn new(username: String) -> Self {
        let mut user = DovecotUser::default();
        user.user = username;
        user
    }

    pub fn get_env_vars(&self) -> HashMap<&'static str, String> {
        let mut extra: Vec<&str> = Vec::new();
        let mut map: HashMap<&'static str, String> = HashMap::new();

        map.insert("USER", self.user.clone());

        if let Some(home) = self.home.as_ref() {
            map.insert("HOME", home.clone());
        }
    
        if let Some(mail) = self.mail.as_ref() {
            map.insert("userdb_mail", mail.clone());
            extra.push("userdb_mail");
        }

        if let Some(uid) = self.uid.as_ref() {
            map.insert("userdb_uid", uid.clone());
            extra.push("userdb_uid");
        }

        if let Some(gid) = self.gid.as_ref() {
            map.insert("userdb_gid", gid.clone());
            extra.push("userdb_gid");
        }

        if let Some(quota_rule) = self.quota_rule.as_ref() {
            map.insert("userdb_quota_rule", quota_rule.clone());
            extra.push("userdb_quota_rule");
        }

        if !extra.is_empty() {
            map.insert("EXTRA", extra.join(" "));
        }
        map
    }
}

fn read_credentials_from_fd(fd: Option<i32>) -> AuthResult<(String, String)> {
    let fd = fd.unwrap_or(INPUT_FD);
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut input = String::new();
    f.read_to_string(&mut input)?;

    let credentials: Vec<&str> = input.split('\0').collect();
    if credentials.len() == 2 {
        Ok((credentials[0].to_string(), credentials[1].to_string()))
    } else {
        Err(Error::TempFail(format!("did not receive credentials on fd {}", fd)))
    }}

pub struct ReplyBin {
    pub reply_bin: CString,
    pub args: Vec<CString>
}

impl ReplyBin {
    pub fn new<B, T>(reply_bin: B, args: Vec<T>) -> Result<Self, NulError>
    where
        B: Into<Vec<u8>>,
        T: Into<Vec<u8>>
    {
        let c_reply_bin = CString::new(reply_bin)?;
        let mut c_args: Vec<CString> = Vec::new();
        for arg in args.into_iter() {
            c_args.push(CString::new(arg)?);
        } 
        Ok(Self {
            reply_bin: c_reply_bin,
            args: c_args
        })
    }

    pub fn call(&self, user: &DovecotUser) -> nix::Result<Infallible> {
        for (env_var, value) in user.get_env_vars() {
            env::set_var(env_var, value);
        }
        execvp(&self.reply_bin, &self.args)
    }
}

pub fn authenticate<L, V, U>(lookup_mod: Option<&L>, verify_mod: Option<&V>, update_mod: Option<&U>, reply_bin: &ReplyBin, fd: Option<i32>) -> AuthResult<Infallible>
where
    L: CredentialsLookup,
    V: CredentialsVerify,
    U: CredentialsUpdate
{
    let (username, password) = read_credentials_from_fd(fd)?;
    let mut user = DovecotUser::new(username);

    let credentials_lookup = env::var("CREDENTIALS_LOOKUP").unwrap_or_default() == "1";

    match lookup_mod {
        Some(module) => {
            module.credentials_lookup(&mut user)?;
            if credentials_lookup {
                if env::var("AUTHORIZED").unwrap_or_default() == "1" {
                    env::set_var("AUTHORIZED", "2");
                }
            }
        },
        None => {
            if credentials_lookup {
                return Err(Error::NoUser);
            }
        }
    }

    if let Some(module) = update_mod {
        module.update_credentials(&user, &password)?;
    }

    if !credentials_lookup {
        match verify_mod {
            Some(module) => {
                module.credentials_verify(&user, &password)?;
            },
            None => {
                return Err(Error::TempFail("unable to verify credentials, very module not loaded".to_string()));
            }
        }
    }

    reply_bin.call(&user).map_err(|err| Error::TempFail(err.to_string()))
}



/*


#[derive(Deserialize)]
pub struct Config {
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

        let remote_ip = env::var("REMOTE_IP").unwrap_or("".to_string());
        if !remote_ip.is_empty() && !user.password.is_empty() && config.db_auth_hosts.contains(&remote_ip) {
            if !hashlib::verify_hash(&password, &user.password) {
                return Err(AuthError::Perm);
            }
        } else {
            authenticator.credentials_verify(&user.user, &password, &scheme)?
        }
    }
    authenticator.call_reply_bin(&user)
}
*/