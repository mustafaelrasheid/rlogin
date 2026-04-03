use clap::Parser;

#[derive(Parser)]
#[command(name = "rlogin")]
#[command(version = "1.0.0")]
#[command(author = "mustafaelrasheid")]
#[command(
    about = "login program that only uses yescript",
    long_about = None
)]
pub struct Args {
    pub path: Option<String>,
}
