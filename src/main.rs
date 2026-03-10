use std::io;
use std::io::{stdout, stdin, Write, Error, ErrorKind};
use std::io::ErrorKind::NotFound;
use std::ffi::CString;
use std::os::fd::{AsRawFd};
use std::fs::{OpenOptions, read_to_string};
use std::env::{set_var, args};
use nix::libc::{ioctl, dup2, TIOCSCTTY};
use nix::unistd::{execv, setuid, setgid, setsid, Uid, Gid};
use termios::{Termios, tcsetattr, TCSAFLUSH, ECHO};
use yescrypt::{Yescrypt, PasswordVerifier as OtherPasswordVerifier};

fn prompt_read_line(prompt: &str, is_hidden: bool) -> io::Result<String> {
    let mut termios = Termios::from_fd(0)?;
    let original = termios.clone();
    let mut input = String::new();

    print!("{}", prompt);
    stdout().flush()?;

    if is_hidden {
        termios.c_lflag &= !ECHO;
        tcsetattr(0, TCSAFLUSH, &termios)?;
    }

    stdin().read_line(&mut input)?;
    
    if is_hidden {
        println!();
        tcsetattr(0, TCSAFLUSH, &original)?;
    }

    return Ok(input.trim().to_string());
}

fn is_valid_username(username: &str) -> bool {
    if username.is_empty() {
        return false;
    }
    return username.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
    });
}

fn get_conf(filename: &str, query: &str) -> io::Result<Vec<String>> {
    let line = read_to_string(filename)?
        .lines()
        .find(|lines| lines.starts_with(query))
        .ok_or_else(|| {
            let err_msg = format!("Invalid {} format", filename);
            Error::new(NotFound, &*err_msg)
        })?
        .to_string();

    let parts: Vec<String> = line.split(':').map(|s| s.to_string()).collect();
    return Ok(parts);
}

fn check_login(username: &str, password: &str) -> io::Result<bool> {
    let query = format!("{}:", username);
    let parts = get_conf("/etc/shadow", &query)?;

    if parts.len() < 2 {
        return Err(
            Error::new(
                ErrorKind::Other,
                "Invalid shadow format")
        );
    }

    let stored_username = &parts[0];
    let stored_hash = &parts[1];

    if stored_username != username {
        return Err(
            Error::new(
                ErrorKind::Other,
                "Typed username and username in shadow don't match")
        );
    }

    let password_hash = yescrypt::PasswordHash::new(stored_hash)
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid hash format"))?;

    let yescrypt = Yescrypt::default();
    match yescrypt.verify_password(password.as_bytes(), &password_hash) {
        Ok(_) => {
            return Ok(true);
        },
        Err(_) => {
            return Err(Error::new(ErrorKind::Other, "Hash verification failed"));
        },
    }
}

fn get_user_info(username: &str) -> io::Result<(u32, u32, String, String)> {
    let query = format!("{}:", username);
    let parts = get_conf("/etc/passwd", &query)?;
    let [_, _, ref uid_str, ref gid_str, _, ref home_dir, ref entry_path] = parts[0..7] else {
        return Err(
            Error::new(
                ErrorKind::Other,
                "Invalid passwd format"));
    };

    let uid = uid_str.parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid UID"))?;
    let gid = gid_str.parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid GID"))?;

    return Ok((uid, gid, home_dir.to_string(), entry_path.to_string()));
}

fn authenticate() -> (String, u32, u32, String, String) {
    loop {
        let username = prompt_read_line("Username: ", false).unwrap_or_else(|e| {
            eprintln!("Failed to read username: {}", e);
            String::new()
        });
        if !is_valid_username(&username) {
            eprintln!("Invalid username. Try again.");
            continue;
        }
        let password = prompt_read_line("Password: ", true).unwrap_or_else(|e| {
            eprintln!("Failed to read password: {}", e);
            String::new()
        });
        let result = check_login(&username, &password).unwrap_or_else(|e| {
            eprintln!("Error: Can't match password. {}", e);
            false
        });

        match result {
            true => {
                match get_user_info(&username) {
                    Ok((uid, gid, home_dir, entry_path)) => {
                        return (username, uid, gid, home_dir, entry_path);
                    },
                    Err(e) => {
                        eprintln!("Error: Failed to get user info. {}", e);
                        continue;
                    }
                }
            },
            false => {
                println!("Username or password don't match. Try again.");
            }
        };
    }
}

fn get_path_arg(default_path: &str) -> String {
    let args: Vec<String> = args().collect();
    let shell_path = if args.len() > 1 {
        args[1].clone()
    } else {
        String::from(default_path)
    };

    return shell_path;
}

fn init_env(username: &str, home_dir: &str) {
    unsafe {
        set_var("HOME", home_dir);
        set_var("USER", username);
    }
}

fn init_tty() {
    const STDIN: i32 = 0;
    const STDOUT: i32 = 1;
    const STDERR: i32 = 2;

    let tty_handler = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
        .or_else(|_| OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/pts/0")
        );
    
    match tty_handler {
        Ok(tty) => {
            let fd = tty.as_raw_fd();
            unsafe {
                let _ = setsid();
                dup2(fd, STDIN);
                dup2(fd, STDOUT);
                dup2(fd, STDERR);
                ioctl(0, TIOCSCTTY, 1);
            }
        },
        Err(e) => {
            eprintln!("Failed to initalized TTY {}", e);
        }
    }
}

fn run(path: &str, uid: u32, gid: u32) {
    let cpath = CString::new(path).expect("Wrong path format");

    setgid(Gid::from_raw(gid)).unwrap_or_else(|e| {
         eprintln!("Failed to set Gid to {} due to {}", gid, e);
    });
    setuid(Uid::from_raw(uid)).unwrap_or_else(|e| {
         eprintln!("Failed to set Uid to {} due to {}", uid, e);
    });
    #[allow(unreachable_code)]{
        execv(&cpath, &[cpath.clone()]).expect(
            &format!("Failed to load {}", path)
        );
    }
}

fn main() {
    let (username, uid, gid, home_dir, entry_path) = authenticate();
    let path = get_path_arg(&entry_path);

    init_env(&username, &home_dir);
    init_tty();
    run(&path, uid, gid);
}
