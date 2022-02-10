mod auth;

const ERR_PERMFAIL: i32 = 1;
const ERR_NOUSER: i32 = 3;
const ERR_TEMPFAIL: i32 = 111;

fn help(myname: &str) {
    println!("Usage: {} REPLYBIN", myname);
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
    let mut reply_bin = &args[1];
    let mut test = false;
    if reply_bin == "test" {
        test = true;
        fd = 0;
        reply_bin = &"/bin/true".to_string();
    }
    std::process::exit(match auth::nextcloud_auth(fd, &format!("{}.toml", myname)) {
        Ok(_) => 0,
        Err(err) => {
            match err {
                auth::AuthError::PermError => {
                    if test {
                        eprintln!("{}", err);
                    }
                    ERR_PERMFAIL
                },
                auth::AuthError::NoUserError => {
                    if test {
                        eprintln!("{}", err);
                    }
                    ERR_NOUSER
                },
                auth::AuthError::TempError(errmsg) => {
                    eprintln!("{}", errmsg);
                    ERR_TEMPFAIL
                },
            }
        }
    });
}
