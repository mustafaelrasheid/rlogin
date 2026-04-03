mod args;

use std::error::Error;
use std::io::{stdout, stdin, Write, Error as IOError};
use std::ffi::CString;
use std::os::fd::{AsRawFd};
use std::fs::{OpenOptions, read_to_string};
use std::env::set_var;
use nix::libc::{ioctl, dup2, TIOCSCTTY};
use nix::unistd::{execv, setuid, setgid, setsid, Uid, Gid};
use termios::{Termios, tcsetattr, TCSAFLUSH, ECHO};
use yescrypt::{Yescrypt, PasswordVerifier as OtherPasswordVerifier};
use clap::Parser;
use crate::args::Args;

fn prompt_read_line(prompt: &str, is_hidden: bool)
-> Result<String, IOError> {
    let mut termios = Termios::from_fd(0)?;
    let original = termios.clone();
    let mut input = String::new();

    print!("{}", prompt);
    stdout().flush()?;

    if is_hidden {
        termios.c_lflag &= !ECHO;
        tcsetattr(
            0,
            TCSAFLUSH,
            &termios
        )?;
    }

    stdin().read_line(&mut input)?;
    
    if is_hidden {
        println!();
        tcsetattr(
            0,
            TCSAFLUSH,
            &original
        )?;
    }

    return Ok(
        input
            .trim()
            .to_string()
    );
}

fn is_valid_username(username: &str) -> bool {
    if username.is_empty() {
        return false;
    }

    return username
        .chars()
        .all(|c| {
            c.is_ascii_alphanumeric()
            || c == '_'
            || c == '-'
            || c == '.'
        });
}

fn get_conf(filename: &str, query: &str)
-> Result<Vec<String>, Box<dyn Error>> {
    let line = read_to_string(filename)?
        .lines()
        .find(|lines| lines.starts_with(&format!("{}:", query)))
        .ok_or(
            format!("Invalid {} format", filename)
        )?
        .to_string();
    let parts: Vec<String> = line
        .split(':')
        .map(|s| s.to_string())
        .collect();

    return Ok(parts);
}

fn check_login(username: &str, password: &str)
-> Result<(), Box<dyn Error>> {
    let yescrypt = Yescrypt::default();
    let parts = get_conf("/etc/shadow", username)?;

    if parts.len() < 2 {
        return Err(
            "Invalid shadow format".into()
        );
    }
    yescrypt.verify_password(
        password.as_bytes(),
        &yescrypt::PasswordHash::new(&parts[1])?
    )?;
    
    return Ok(());
}

fn get_user_info(username: &str)
-> Result<(u32, u32, String, String), Box<dyn Error>> {
    let parts = get_conf("/etc/passwd", username)?;
    let [_, _, ref uid, ref gid, _, ref home_dir, ref shell_path]
        = parts[0..7] else {
        return Err(
            "Invalid passwd format"
        .into());
    };

    return Ok((
        uid.parse::<u32>()?,
        gid.parse::<u32>()?,
        home_dir.to_string(),
        shell_path.to_string()
    ));
}

fn authenticate() -> (String, u32, u32, String, String) {
    loop {
        let username = prompt_read_line("Username: ", false)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read username: {}", e);
                String::new()
            });
        let password = prompt_read_line("Password: ", true)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read password: {}", e);
                String::new()
            });
        
        if !is_valid_username(&username) {
            eprintln!("Invalid username. Try again.");
            continue;
        }
        if let Err(e) = check_login(&username, &password) {
            eprintln!("Error: Can't match password due to {}", e);
            continue;
        }
        
        match get_user_info(&username) {
            Ok((uid, gid, home_dir, shell_path)) => {
                return (username, uid, gid, home_dir, shell_path);
            },
            Err(e) => {
                eprintln!("Error: Failed to get user info due to {}", e);
                continue;
            }
        }
    }
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
            eprintln!("Failed to initalized TTY due to {}", e);
        }
    }
}

fn run(path: &str, uid: u32, gid: u32) {
    let cpath = CString::new(path).expect("Wrong path format");

    setgid(Gid::from_raw(gid))
        .unwrap_or_else(|e| {
             eprintln!("Failed to set Gid to {} due to {}", gid, e);
             panic!();
        });
    setuid(Uid::from_raw(uid))
        .unwrap_or_else(|e| {
             eprintln!("Failed to set Uid to {} due to {}", uid, e);
             panic!();
        });
    #[allow(unreachable_code)]{
        execv(&cpath, &[cpath.clone()]).expect(
            &format!("Failed to load {}", path)
        );
    }
}

fn main() {
    let args = Args::parse();
    let (username, uid, gid, home_dir, shell_path) = authenticate();

    init_env(&username, &home_dir);
    init_tty();
    run(
        &args.path.unwrap_or(shell_path),
        uid,
        gid
    );
}
