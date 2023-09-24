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

use super::{AuthResult, CredentialsVerify, DovecotUser, Error};

use base64::{engine::general_purpose, Engine as _};
use urlencoding::encode;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HttpVerifyConfig {
    pub url: String,
    pub method: String,
    pub ok_code: u16,
    pub invalid_code: u16,
}

impl Default for HttpVerifyConfig {
    fn default() -> Self {
        Self {
            url: String::from("https://localhost/auth"),
            method: String::from("GET"),
            ok_code: 200,
            invalid_code: 403,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpVerifyModule {
    config: HttpVerifyConfig,
}

impl HttpVerifyModule {
    pub fn new(config: HttpVerifyConfig) -> Self {
        Self { config }
    }
}

impl CredentialsVerify for HttpVerifyModule {
    fn credentials_verify(&self, user: &DovecotUser, password: &str) -> AuthResult<()> {
        let username = encode(&user.user);
        let url = self.config.url.replace("::USERNAME::", &username);

        let credentials = general_purpose::STANDARD.encode(format!("{}:{password}", user.user));
        let authorization = format!("Basic {credentials}");

        let request = ureq::request(&self.config.method, &url).set("Authorization", &authorization);

        match request.call() {
            Ok(res) => {
                let code = res.status();
                if code == self.config.ok_code {
                    Ok(())
                } else {
                    Err(Error::TempFail(format!(
                        "unexpected http response: {code} {}",
                        res.status_text()
                    )))
                }
            }
            Err(ureq::Error::Status(code, res)) => {
                if code == self.config.invalid_code {
                    Err(Error::PermFail)
                } else {
                    Err(Error::TempFail(format!(
                        "unexpected http error response: {code} {}",
                        res.status_text()
                    )))
                }
            }
            Err(err) => Err(Error::TempFail(format!("unable to reach server: {err}"))),
        }
    }
}