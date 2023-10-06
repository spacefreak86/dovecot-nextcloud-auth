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

//! Dovecot-Auth is an implementation of the Checkpassword interface which is used by the Dovecot SASL server.
//!
//! See <https://doc.dovecot.org/configuration_manual/authentication/checkpassword/> for more information.
//!

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

/// Trait which defines credentials lookup modules
pub trait CredentialsLookup {
    fn credentials_lookup(&mut self, user: &mut DovecotUser) -> AuthResult<()>;
}

/// Trait which defines post lookup modules
pub trait PostLookup {
    fn post_lookup(&mut self, user: &mut DovecotUser, password: &str) -> AuthResult<()>;
}

/// Trait which defines credentials verify modules
pub trait CredentialsVerify {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<()>;
}

/// Trait which defines cached credentials verify modules
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
    fn cached_credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<()> {
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
        debug!("try to verify password against cached verified hashes");
        if find_hash(password, &verified_hashes).is_some() {
            debug!("verification against cached verified hash succeeded");
            return Ok(());
        }

        let expired_hash = find_hash(password, &expired_hashes).cloned();
        debug!("verify credentials by credentials verify module");
        let res = match self.module().credentials_verify(user, password) {
            Ok(()) => {
                debug!("verification succeeded, insert hash into cache");
                let hash = expired_hash.unwrap_or_else(|| self.hash(password));
                self.insert(&user.username, hash).unwrap_or_else(|err| {
                    warn!("unable to insert hash into cache: {err}");
                });
                Ok(())
            }
            Err(AuthError::PermFail) => {
                if let Some(hash) = expired_hash {
                    self.delete(&user.username, &hash).unwrap_or_else(|err| {
                        warn!("unable to delete hash from cache: {err}");
                    });
                }
                Err(AuthError::PermFail)
            }
            Err(err) => match self.allow_expired_on_error() {
                true => {
                    warn!("credentials verify module failed: {err}");
                    warn!("try to verify password against expired hashes");
                    match expired_hash {
                        Some(_) => {
                            debug!("verification against expired hashes succeeded");
                            Ok(())
                        }
                        None => {
                            debug!("verification against expired hashes failed");
                            Err(AuthError::PermFail)
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
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<()> {
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

    pub fn verify(user: &DovecotUser, password: &str) -> bool {
        match user
            .password
            .as_ref()
            .and_then(|p| Hash::try_from(p.as_str()).ok())
        {
            Some(hash) => verify_value(password, &hash),
            None => false,
        }
    }
}

impl CredentialsVerify for InternalVerifyModule {
    fn credentials_verify(&mut self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        match Self::verify(user, password) {
            true => Ok(()),
            false => Err(AuthError::PermFail),
        }
    }
}

/// Represents a credentials lookup module
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LookupModule {
    #[cfg(feature = "db")]
    DB(db::DBLookupConfig),
}

/// Represents a post lookup credentials module
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PostLookupModule {
    #[cfg(feature = "db")]
    DBUpdateCredentials(db::DBUpdateCredentialsConfig),
}

/// Represents a credentials verify module
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum VerifyModule {
    Internal,
    #[cfg(feature = "http")]
    Http(http::HttpVerifyConfig),
}

/// Represents a cached credentials verify module
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum VerifyCacheModule {
    #[cfg(feature = "db")]
    DB(db::DBCacheVerifyConfig),
    #[cfg(feature = "serde")]
    File(file::FileCacheVerifyConfig),
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
/// The input is expected to be in this format: &lt;username&gt;NUL&lt;password&gt;[NUL...]
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
    user: &mut DovecotUser,
    mut module: Box<dyn CredentialsLookup>,
) -> AuthResult<()> {
    debug!("credentials lookup, user {}", user.username);
    module.credentials_lookup(user)?;
    debug!("credentials lookup succeeded data: {:?}", user);
    if env::var("AUTHORIZED").unwrap_or_default() == "1" {
        env::set_var("AUTHORIZED", "2");
    }
    Ok(())
}

fn verify_internal_if_allowed(
    user: &DovecotUser,
    password: &str,
    allowed_hosts: &[String],
) -> bool {
    let remote_ip = env::var("REMOTE_IP").unwrap_or_default();
    if remote_ip.is_empty() {
        return false;
    }

    debug!("got remote IP from environment variable REMOTE_IP: {remote_ip}");
    if !allowed_hosts.contains(&remote_ip) {
        return false;
    }

    debug!("try to internally verify user credentials");
    let res = InternalVerifyModule::verify(user, password);
    match res {
        true => info!("internal verification succeeded"),
        false => debug!("internal verification failed"),
    }
    res
}

fn credentials_verify(
    user: &mut DovecotUser,
    password: String,
    mut verify_module: Box<dyn CredentialsVerify>,
    allow_internal_verify_hosts: Option<Vec<String>>,
) -> AuthResult<()> {
    debug!("verify credentials of user {}", user.username);

    let verified = match allow_internal_verify_hosts {
        Some(hosts) => {
            debug!("allowed for internal verification: {:?}", hosts);
            verify_internal_if_allowed(user, &password, &hosts)
        }
        None => false,
    };

    if !verified {
        verify_module.credentials_verify(user, &password)?;
    }
    info!("credentials verify succeeded");
    Ok(())
}

pub fn authenticate(
    lookup_module: Option<Box<dyn CredentialsLookup>>,
    post_lookup_module: Option<Box<dyn PostLookup>>,
    verify_module: Option<Box<dyn CredentialsVerify>>,
    allow_internal_verify_hosts: Option<Vec<String>>,
    reply_bin: ReplyBin,
    fd: Option<i32>,
) -> AuthResult<Infallible> {
    let (username, password) = read_credentials_from_fd(fd)?;
    let mut user = DovecotUser::new(username);

    let lookup_res = lookup_module.map(|module| credentials_lookup(&mut user, module));
    if lookup_res.is_some() {
        if let Some(mut module) = post_lookup_module {
            module.post_lookup(&mut user, &password).unwrap_or_else(|err| {
                warn!("error in post lookup module: {err}");
            });
        }
    }

    match env::var("CREDENTIALS_LOOKUP").unwrap_or_default().as_str() {
        "1" => match lookup_res {
            Some(res) => res,
            None => Err(AuthError::TempFail(
                "unable to lookup credentials without a lookup module".to_string(),
            )),
        },
        _ => {
            if let Some(res) = lookup_res {
                match res {
                    Ok(()) => (),
                    Err(AuthError::NoUser) => debug!("no user data found"),
                    Err(err) => warn!("error during credentials_lookup: {err}"),
                };
            }

            match verify_module {
                Some(verify_module) => credentials_verify(
                    &mut user,
                    password,
                    verify_module,
                    allow_internal_verify_hosts,
                ),
                None => Err(AuthError::TempFail(
                    "unable to verify credentials without a very module".to_string(),
                )),
            }
        }
    }?;

    reply_bin
        .call(user)
        .map_err(|err| AuthError::TempFail(format!("unable to call reply_bin: {err}")))
}
