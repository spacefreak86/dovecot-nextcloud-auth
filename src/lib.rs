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
pub mod db;

#[cfg(feature = "serde")]
pub mod file;

pub mod hashlib;

#[cfg(feature = "http")]
pub mod http;

use hashlib::*;
use log::{debug, info, warn};
use nix::unistd::execvp;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::ffi::{CString, NulError};
use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

/// Exit code to signal invalid credentials
pub const DOVECOT_PERMFAIL: i32 = 1;
/// Exit code to signal user not found
pub const DOVECOT_NOUSER: i32 = 3;
/// Exit code to signal temporary failures
pub const DOVECOT_TEMPFAIL: i32 = 111;
/// Default file descriptor to read credentials from
pub const DOVECOT_INPUT_FD: i32 = 3;

/// Represents an exit code for Dovecot
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Invalid credentials
    PermFail,
    /// User not found
    NoUser,
    /// Temporary failure
    TempFail(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthError::PermFail => write!(f, "invalid credentials"),
            AuthError::NoUser => write!(f, "user not found"),
            AuthError::TempFail(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    /// Returns the corresponding exit code for Dovecot
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PermFail => DOVECOT_PERMFAIL,
            Self::NoUser => DOVECOT_NOUSER,
            Self::TempFail(_) => DOVECOT_TEMPFAIL,
        }
    }
}

impl From<std::io::Error> for AuthError {
    fn from(error: std::io::Error) -> Self {
        AuthError::TempFail(error.to_string())
    }
}

#[cfg(feature = "serde")]
impl From<toml::de::Error> for AuthError {
    fn from(value: toml::de::Error) -> Self {
        AuthError::TempFail(value.to_string())
    }
}

pub type AuthResult<T> = Result<T, AuthError>;

/// Represents a Dovecot user
#[derive(Debug, Clone, Default)]
pub struct DovecotUser {
    pub username: String,
    pub password: Option<String>,
    pub home: Option<String>,
    pub userdb_mail: Option<String>,
    pub userdb_uid: Option<String>,
    pub userdb_gid: Option<String>,
    pub userdb_quota_rule: Option<String>,
}

impl DovecotUser {
    /// Returns a Dovecot user with the username given
    pub fn new<T: AsRef<str>>(username: T) -> Self {
        Self {
            username: username.as_ref().to_string(),
            ..Default::default()
        }
    }

    /// Returns a HashMap containing environment variables
    ///
    /// It is used to hand over user information to Dovecot
    pub fn get_env_vars(&self) -> HashMap<&'static str, String> {
        let mut extra: Vec<&str> = Vec::new();
        let mut map: HashMap<&'static str, String> = HashMap::new();

        map.insert("USER", self.username.clone());

        if let Some(home) = self.home.as_ref() {
            map.insert("HOME", home.clone());
        }

        if let Some(mail) = self.userdb_mail.as_ref() {
            map.insert("userdb_mail", mail.clone());
            extra.push("userdb_mail");
        }

        if let Some(uid) = self.userdb_uid.as_ref() {
            map.insert("userdb_uid", uid.clone());
            extra.push("userdb_uid");
        }

        if let Some(gid) = self.userdb_gid.as_ref() {
            map.insert("userdb_gid", gid.clone());
            extra.push("userdb_gid");
        }

        if let Some(quota_rule) = self.userdb_quota_rule.as_ref() {
            map.insert("userdb_quota_rule", quota_rule.clone());
            extra.push("userdb_quota_rule");
        }

        if !extra.is_empty() {
            map.insert("EXTRA", extra.join(" "));
        }
        map
    }
}

/// Trait which defines credentials lookup modules used by the authenticate function
pub trait CredentialsLookup {
    fn credentials_lookup(&mut self, user: &mut DovecotUser) -> AuthResult<bool>;
}

/// Trait which defines credentials verify modules used by the authenticate function
pub trait CredentialsVerify {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool>;
}

/// Trait which defines update credentials modules used by the authenticate function
pub trait CredentialsUpdate {
    fn update_credentials(&self, user: &DovecotUser, password: &str) -> AuthResult<bool>;
}

/// Trait which defines cached credentials verify modules used by the authenticate function
pub trait CredentialsVerifyCache: CredentialsVerify {
    // Return the hash of the password given
    fn hash(&self, password: &str) -> Hash;
    // Return a tuple of verified and expired hashes of the user given
    fn get_hashes(&self, user: &str) -> AuthResult<(Vec<Hash>, Vec<Hash>)>;
    // Insert a Hash into the cache
    fn insert(&mut self, user: &str, hash: Hash) -> AuthResult<()>;
    // Delete a Hash from the cache
    fn delete(&mut self, user: &str, hash: &Hash) -> AuthResult<()>;
    // Clean the cache (e.g. delete expired hashes)
    fn cleanup(&mut self) -> AuthResult<()>;
    // Return a mutable reference to the configured credentials verify module
    fn module(&mut self) -> &mut Box<dyn CredentialsVerify>;
    // Return true if expired hashes are allowed on an error within the credentials verify module
    fn allow_expired_on_error(&self) -> bool;
    // Save the cache (e.g. to disk)
    fn save(&self) -> AuthResult<()>;
    // Default implementation of a cached credentials verify procedure, should be sufficient for almost all cases
    fn cached_credentials_verify(
        &mut self,
        user: &DovecotUser,
        password: &str,
    ) -> AuthResult<bool> {
        debug!("verify credentials (cached)");
        self.cleanup().unwrap_or_else(|err| {
            warn!("unable to cleanup cache: {err}");
        });

        let (verified_hashes, expired_hashes) =
            self.get_hashes(&user.username).unwrap_or_else(|err| {
                warn!("unable to get hashes from cache: {err}");
                Default::default()
            });
        debug!("verified hashes: {:?}", verified_hashes);
        debug!("try to verify credentials against cached verified hashes");
        if find_hash(password, &verified_hashes).is_some() {
            debug!("verified against cached verified hash successfully");
            return Ok(true);
        }

        let expired_hash = find_hash(password, &expired_hashes).cloned();
        debug!("verify credentials with verification module");
        let res = match self.module().credentials_verify(user, password) {
            Ok(true) => {
                debug!("verification succeeded, insert hash into cache");
                let hash = expired_hash.unwrap_or_else(|| self.hash(password));
                self.insert(&user.username, hash).unwrap_or_else(|err| {
                    warn!("unable to insert hash into cache: {err}");
                });
                Ok(true)
            }
            Ok(false) => {
                if let Some(hash) = expired_hash {
                    self.delete(&user.username, &hash).unwrap_or_else(|err| {
                        warn!("unable to delete hash from cache: {err}");
                    });
                }
                Ok(false)
            }
            Err(err) => match self.allow_expired_on_error() {
                true => {
                    warn!("verification module failed: {err}");
                    warn!("try to verify against expired hashes");
                    match expired_hash {
                        Some(_) => {
                            debug!("verification against expired hashes succeeded");
                            Ok(true)
                        }
                        None => {
                            debug!("verification against expired hashes failed");
                            Ok(false)
                        }
                    }
                }
                false => Err(err),
            },
        };

        if let Err(err) = self.save() {
            warn!("unable to save verify cache: {err}");
        }

        res
    }
}

impl<T: CredentialsVerifyCache> CredentialsVerify for T {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool> {
        self.cached_credentials_verify(user, password)
    }
}

/// Internal credentials verify module
///
/// Verifies passwords internally by verifying it against the password hash returned by the credentials lookup module
#[derive(Debug, Default, Clone)]
pub struct InternalVerifyModule {}

impl InternalVerifyModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialsVerify for InternalVerifyModule {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<bool> {
        match user
            .password
            .as_ref()
            .and_then(|p| Hash::try_from(p.as_str()).ok())
        {
            Some(hash) => Ok(verify_value(password, &hash)),
            None => Ok(false),
        }
    }
}

/// Represents a credentials lookup module
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum LookupModule {
    #[cfg(feature = "db")]
    DB(db::DBLookupConfig),
}

/// Represents a credentials verify module
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum VerifyModule {
    Internal,
    #[cfg(feature = "http")]
    Http(http::HttpVerifyConfig),
}

/// Represents a cached credentials verify module
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum VerifyCacheModule {
    #[cfg(feature = "db")]
    DB(db::DBCacheVerifyConfig),
    #[cfg(feature = "serde")]
    File(file::FileCacheVerifyConfig),
}

/// Represents an update credentials module
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type"))]
pub enum UpdateCredentialsModule {
    #[cfg(feature = "db")]
    DB(db::DBUpdateCredentialsConfig),
}

/// Represents the path to a reply binary and arguments to call it with
pub struct ReplyBin {
    pub reply_bin: CString,
    pub args: Vec<CString>,
}

impl ReplyBin {
    /// Returns a reply binary by the binary and arguments given
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

    /// Sets environment variables for Dovecot and calls the reply binary
    ///
    /// The reply binary is called with execvp. The current process image will be replaced
    /// by the new one, which means that this program actually ends with the call of this function
    pub fn call(&self, user: DovecotUser) -> nix::Result<Infallible> {
        for (env_var, value) in user.get_env_vars() {
            env::set_var(env_var, value);
        }
        execvp(&self.reply_bin, &self.args)
    }
}

/// Returns a tuple containg a username and a password
///
/// Reads credentials from the raw file descriptor optionally given (defaults to 3).
/// The input is expected to be in this format: username<NUL>password[<NUL>...]
pub fn read_credentials_from_fd(fd: Option<i32>) -> AuthResult<(String, String)> {
    let fd = fd.unwrap_or(DOVECOT_INPUT_FD);
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut input = String::new();
    f.read_to_string(&mut input)?;
    let credentials: Vec<&str> = input.split('\0').collect();
    if credentials.len() >= 2 {
        Ok((credentials[0].to_string(), credentials[1].to_string()))
    } else {
        Err(AuthError::TempFail(format!(
            "did not receive credentials on fd {fd}"
        )))
    }
}

pub fn credentials_lookup(
    mut user: DovecotUser,
    mut module: Box<dyn CredentialsLookup>,
    reply_bin: ReplyBin,
) -> AuthResult<Infallible> {
    debug!("credentials lookup, user {}", user.username);
    if !module.credentials_lookup(&mut user)? {
        return Err(AuthError::NoUser);
    }
    debug!("got user data: {:?}", user);
    if env::var("AUTHORIZED").unwrap_or_default() == "1" {
        env::set_var("AUTHORIZED", "2");
    }
    reply_bin
        .call(user)
        .map_err(|err| AuthError::TempFail(format!("unable to call reply_bin: {err}")))
}

fn credentials_verify(
    mut user: DovecotUser,
    password: String,
    lookup_module: Option<Box<dyn CredentialsLookup>>,
    mut verify_module: Box<dyn CredentialsVerify>,
    update_module: Option<Box<dyn CredentialsUpdate>>,
    reply_bin: ReplyBin,
    allow_internal_verify_hosts: Option<Vec<String>>,
) -> AuthResult<Infallible> {
    debug!("verify credentials of user {}", user.username);

    let mut internal_verified = false;

    if let Some(mut module) = lookup_module {
        debug!("lookup up user data");
        match module.credentials_lookup(&mut user) {
            Ok(true) => {
                debug!("got user data: {:?}", user);

                if let Some(module) = update_module {
                    match module.update_credentials(&user, &password) {
                        Ok(true) => debug!("successfully updated credentials"),
                        Ok(false) => debug!("credentials where not updated"),
                        Err(err) => warn!("unable to update credentials: {err}"),
                    }
                }

                if let Some(allowed) = allow_internal_verify_hosts {
                    debug!("allowed for internal verification: {:?}", allowed);
                    if let Ok(remote_ip) = env::var("REMOTE_IP") {
                        debug!("got env variable REMOTE_IP={remote_ip}");
                        if !remote_ip.is_empty() && allowed.contains(&remote_ip) {
                            debug!("try internally verificate user credentials");
                            if InternalVerifyModule::new().credentials_verify(&user, &password)? {
                                info!("internal verification succeeded");
                                internal_verified = true;
                            } else {
                                debug!("internal verification failed");
                            }
                        }
                    }
                }
            }
            Ok(false) => {
                debug!("no user data found");
            }
            Err(err) => {
                warn!("error during credentials_lookup: {err}");
            }
        }
    }

    if !internal_verified {
        if !verify_module.credentials_verify(&user, &password)? {
            return Err(AuthError::PermFail);
        }
        info!("verification succeeded");
    }

    reply_bin
        .call(user)
        .map_err(|err| AuthError::TempFail(format!("unable to call reply_bin: {err}")))
}

pub fn authenticate(
    lookup_module: Option<Box<dyn CredentialsLookup>>,
    verify_module: Option<Box<dyn CredentialsVerify>>,
    update_module: Option<Box<dyn CredentialsUpdate>>,
    allow_internal_verify_hosts: Option<Vec<String>>,
    reply_bin: ReplyBin,
    fd: Option<i32>,
) -> AuthResult<Infallible> {
    let (username, password) = read_credentials_from_fd(fd)?;
    let user = DovecotUser::new(username);

    match env::var("CREDENTIALS_LOOKUP").unwrap_or_default().as_str() {
        "1" => match lookup_module {
            Some(module) => {
                credentials_lookup(user, module, reply_bin)
            }
            None => Err(AuthError::NoUser)
        },
        _ => {
            match verify_module {
                Some(module) => {
                    credentials_verify(
                        user,
                        password,
                        lookup_module,
                        module,
                        update_module,
                        reply_bin,
                        allow_internal_verify_hosts,
                    )
                }
                None => Err(AuthError::TempFail("unable to verify credentials without a very module".to_string()))
            }
        }
    }
}
