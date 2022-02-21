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

mod dovecot;

use dovecot::{authenticate, error::AuthError};

const ERR_PERMFAIL: i32 = 1;
const ERR_NOUSER: i32 = 3;
const ERR_TEMPFAIL: i32 = 111;
const TEST_REPLY_BIN: &str = "/bin/true";

fn help(myname: &str) {
    println!("Usage: {} [test] REPLYBIN", myname);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let myname = String::from("dovecot-nextcloud-auth");

    if args.len() < 2 {
        eprintln!("{myname}: missing operand");
        help(&myname);
        std::process::exit(255);
    } else if args[1] == "help" || args[1].starts_with("-h") {
        help(&myname);
        std::process::exit(0);
    }

    let mut fd = 3;
    let mut reply_bin = String::from(&args[1]);
    let mut test = false;
    if reply_bin == "test" {
        // in test mode, read credentials from fd 0 (stdin)
        test = true;
        fd = 0;
        if args.len() > 2 {
            reply_bin = String::from(&args[2]);
        } else {
            reply_bin = String::from(TEST_REPLY_BIN);
        }
    }

    std::process::exit(match authenticate(fd, &format!("{}.toml", args[0]), &reply_bin, test) {
        Ok(()) => 0,
        Err(err) => {
            match err {
                AuthError::PermError => {
                    if test {
                        eprintln!("{}", err);
                    }
                    ERR_PERMFAIL
                },
                AuthError::NoUserError => {
                    if test {
                        eprintln!("{}", err);
                    }
                    ERR_NOUSER
                },
                AuthError::TempError(errmsg) => {
                    eprintln!("{}", errmsg);
                    ERR_TEMPFAIL
                },
            }
        }
    });
}
