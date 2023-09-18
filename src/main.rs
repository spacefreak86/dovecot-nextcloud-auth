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

pub mod dovecot;

use dovecot::{ReplyBin, Error, RC_TEMPFAIL, authenticate};
use config_file::FromConfigFile;

use dovecot::modules::db::{DBLookupModule, DBLookupConfig, DBCacheVerifyModule, DBCacheVerifyConfig, DBUpdateCredentialsModule, DBUpdateCredentialsConfig};
use dovecot::modules::http::{HttpVerifyModule, HttpVerifyConfig};

const TEST_REPLY_BIN: &str = "/bin/true";

fn help(myname: &str) {
    println!("Usage: {} [test] REPLYBIN", myname);
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let myname = String::from("dovecot-nextcloud-auth");

    if args.len() < 2 {
        eprintln!("{myname}: missing operand");
        help(&myname);
        std::process::exit(255);
    } else if args[1] == "help" || args[1].starts_with("-h") {
        help(&myname);
        std::process::exit(0);
    }

    let config_file = format!("{}.toml", args.remove(0));
    let mut reply_bin = args.remove(0);
    let mut fd = None;
    let mut test = false;

    if reply_bin == "test" {
        test = true;
        // in test mode, read credentials from fd 0 (stdin)
        fd = Some(0);
        if !args.is_empty() {
            reply_bin = args.remove(0);
        } else {
            reply_bin = String::from(TEST_REPLY_BIN);
        }
    }

    let reply_bin = ReplyBin::new(reply_bin, args).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(RC_TEMPFAIL);
    });

    let db_config = DBLookupConfig::from_config_file(&config_file).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(RC_TEMPFAIL);
    });

    let conn_pool = dovecot::modules::db::get_conn_pool("DBURL").unwrap();
    let lookup_mod = DBLookupModule::new(db_config, &conn_pool);
    
    let http_config = HttpVerifyConfig::from_config_file(&config_file).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(RC_TEMPFAIL);
    });
    let http_mod = HttpVerifyModule::new(http_config);

    let verify_config = DBCacheVerifyConfig::from_config_file(config_file).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(RC_TEMPFAIL);
    });
    let verify_mod = DBCacheVerifyModule::new(verify_config, &conn_pool, http_mod);

    let update_mod: Option<&DBUpdateCredentialsModule> = None;
    std::process::exit(match authenticate(Some(&lookup_mod), Some(&verify_mod), update_mod, &reply_bin, fd) {
        Ok(_) => 0,
        Err(err) => {
            match &err {
                Error::PermFail|Error::NoUser => {
                    if test {
                        eprintln!("{}", err);
                    }
                },
                Error::TempFail(msg) => {
                    eprintln!("{}", msg);
                },
            }
            err.exit_code()
        }
    });
}
