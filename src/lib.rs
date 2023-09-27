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

pub mod hashlib;
pub mod modules;

use nix::unistd::execvp;
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::ffi::{CString, NulError};
use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

use modules::{CredentialsLookup, CredentialsUpdate, CredentialsVerify, InternalVerifyModule};

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
            Self::TempFail(_) => RC_TEMPFAIL,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::TempFail(error.to_string())
    }
}

#[cfg(feature = "serde")]
impl From<toml::de::Error> for Error {
    fn from(value: toml::de::Error) -> Self {
        Error::TempFail(value.to_string())
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
        Self {
            user: username,
            ..Default::default()
        }
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
    if credentials.len() >= 2 {
        Ok((credentials[0].to_string(), credentials[1].to_string()))
    } else {
        Err(Error::TempFail(format!(
            "did not receive credentials on fd {fd}"
        )))
    }
}

pub struct ReplyBin {
    pub reply_bin: CString,
    pub args: Vec<CString>,
}

impl ReplyBin {
    pub fn new<B, T>(reply_bin: B, args: Vec<T>) -> Result<Self, NulError>
    where
        B: Into<Vec<u8>>,
        T: Into<Vec<u8>>,
    {
        let c_reply_bin = CString::new(reply_bin)?;
        let mut c_args: Vec<CString> = Vec::new();
        for arg in args.into_iter() {
            c_args.push(CString::new(arg)?);
        }
        Ok(Self {
            reply_bin: c_reply_bin,
            args: c_args,
        })
    }

    pub fn call(&self, user: &DovecotUser) -> nix::Result<Infallible> {
        for (env_var, value) in user.get_env_vars() {
            env::set_var(env_var, value);
        }
        execvp(&self.reply_bin, &self.args)
    }
}

pub fn authenticate(
    lookup_mod: &Option<Box<dyn CredentialsLookup>>,
    verify_mod: &Option<Box<dyn CredentialsVerify>>,
    update_mod: &Option<Box<dyn CredentialsUpdate>>,
    allow_internal_verify_hosts: &Option<Vec<String>>,
    reply_bin: &ReplyBin,
    fd: Option<i32>,
) -> AuthResult<Infallible> {
    let (username, password) = read_credentials_from_fd(fd)?;
    let mut user = DovecotUser::new(username);

    if env::var("CREDENTIALS_LOOKUP").unwrap_or_default() == "1" {
        match lookup_mod {
            Some(module) => {
                module.credentials_lookup(&mut user)?;
                if env::var("AUTHORIZED").unwrap_or_default() == "1" {
                    env::set_var("AUTHORIZED", "2");
                }
            }
            None => {
                return Err(Error::NoUser);
            }
        }
    } else {
        if let Some(module) = lookup_mod {
            if module.credentials_lookup(&mut user).is_ok() {
                if let Some(module) = update_mod {
                    module.update_credentials(&user, &password)?;
                }
            }
        }

        let mut internal_verified = false;

        if let Some(allowed) = allow_internal_verify_hosts {
            if let Ok(remote_ip) = env::var("REMOTE_IP") {
                if !remote_ip.is_empty()
                    && allowed.contains(&remote_ip)
                    && InternalVerifyModule::new()
                        .credentials_verify(&user, &password)
                        .is_ok()
                {
                    internal_verified = true;
                }
            }
        }

        if !internal_verified {
            match verify_mod {
                Some(module) => {
                    module.credentials_verify(&user, &password)?;
                }
                None => {
                    return Err(Error::TempFail(
                        "unable to verify credentials, very module not loaded".to_string(),
                    ));
                }
            };
        }
    };

    reply_bin
        .call(&user)
        .map_err(|err| Error::TempFail(format!("unable to call reply_bin: {err}")))
}
