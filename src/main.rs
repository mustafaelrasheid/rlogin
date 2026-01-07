use std::io;
use std::io::{stdout, stdin, Write};
use std::ffi::CString;
use std::os::fd::{AsRawFd};
use std::fs::{read_to_string, OpenOptions};
use std::env::{set_var, args};
use nix::libc::{ioctl, dup2, TIOCSCTTY};
use nix::unistd::{execv, setuid, setgid, setsid, Uid, Gid};
use sha2::{Sha256, Digest};
use termios::{Termios, tcsetattr, TCSAFLUSH, ECHO};

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

fn hex_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hashed_input = hasher.finalize();
    return hex::encode(hashed_input);
}

fn check_login(username: &str, password: &str) -> io::Result<bool> {
    let login_filename = if username == "root" {
        String::from("/root/.login")
    } else {
        format!("/home/{}/.login", username)
    };
    let file = read_to_string(&login_filename)?;
    let parts: Vec<&str> = file.trim().split(':').collect();
    let [stored_username, stored_salt, stored_hash, stored_permission] = parts[0..4] else {
        return Err(
        io::Error::new(
            io::ErrorKind::Other,
            "Invalid .login format"))
    };
    
    if stored_username != username {
        return Err(
            io::Error::new(
                io::ErrorKind::Other,
                "Typed username and username in config files don't match")
        );
    }
    match stored_permission {
        "admin" => (),
        "user" => {
            if username == "root"{
                return Err(
                    io::Error::new(
                        io::ErrorKind::Other,
                        "Invalid permission level set for root user")
                );
            }
        },
        role => {
            let err_msg = format!(
                "Permission {} doesn't exists (allowed permission rules: user, admin)",
                role);
            return Err(
                io::Error::new(
                    io::ErrorKind::Other,
                    &*err_msg)
            );
        }
    }

    let key = hex_hash(&format!("{}{}", password,stored_salt));
    return Ok(key == stored_hash);
}

fn run(path: &str){
    let cpath = CString::new(path).expect("Wrong path format");

    setgid(Gid::from_raw(1000)).unwrap_or_else(|e| {
         eprintln!("Failed to set Gid to 1000 due to {}", e);
    });
    setuid(Uid::from_raw(1000)).unwrap_or_else(|e| {
         eprintln!("Failed to set Uid to 1000 due to {}", e);
    });
    #[allow(unreachable_code)]{
        execv(&cpath, &[cpath.clone()]).expect(
            &format!("Failed to load {}", path)
        );
    }
}

fn authenticate() -> (String, String) {
    loop {
        let username = prompt_read_line("Username: ", false).unwrap_or_else(|e| {
            eprintln!("Failed to read username: {}", e);
            String::new()
        });
        let password = prompt_read_line("Password: ", true).unwrap_or_else(|e| {
            eprintln!("Failed to read username: {}", e);
            String::new()
        });
        let result = check_login(&username, &password).unwrap_or_else(|e| {
            eprintln!("Error: Can't match password. {}", e);
            false
        });

        match result {
            true => {
                return (username, password);
            },
            false => {
                println!("Username or password don't match. Try again.");
            }
        };
    }
}

unsafe fn init_tty() {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
        .or_else(|_| OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/pts/0")) {
        Ok(tty) => {
            let fd = tty.as_raw_fd();
            unsafe {
                let _ = setsid();
                const STDIN: i32 = 0;
                const STDOUT: i32 = 1;
                const STDERR: i32 = 2;
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

fn init_env(username: &str){
    let home_dir = if username == "root" {
        String::from("/root")
    } else {
        format!("/home/{}", username)
    };
    unsafe {
        set_var("HOME", &home_dir);
        set_var("USER", &username);
    }
}

fn get_path_arg() -> String {
    const DEFAULT_PATH: &str = "/usr/bash";
    let args: Vec<String> = args().collect();
    let shell_path = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("No program specified to run after login, using {} as default", DEFAULT_PATH);
        String::from(DEFAULT_PATH)
    };

    return shell_path;
}

fn main() {
    let (username, _) = authenticate();
    let path = get_path_arg();

    init_env(&username);

    unsafe{
        init_tty();
    }

    run(&path);
}
