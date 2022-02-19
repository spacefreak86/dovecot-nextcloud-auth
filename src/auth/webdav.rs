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

use ureq;
use super::error::AuthError;

pub fn verify_credentials(username: &str, password: &str, url: &str) -> std::result::Result<bool, AuthError> {
    let authorization = String::from("Basic ") + &base64::encode(format!("{}:{}", username, password));
    match ureq::request("PROPFIND", &url).set("Authorization", &authorization).call() {
        Ok(res) => {
            let code = res.status();
            if code == 207 {
                Ok(true)
            } else {
                Err(AuthError::TempError(format!("unexpected http response: {} {}", code, res.status_text()).to_owned()))
            }
        },
        Err(ureq::Error::Status(code, res)) => {
            if code == 401 {
                Ok(false)
            } else {
                Err(AuthError::TempError(format!("unexpected http error response: {} {}", code, res.status_text()).to_owned()))
            }
        },
        Err(err) => Err(AuthError::TempError(format!("unable to reach server: {}", err.to_string())))
    }
}
