use clap::Parser;

#[derive(Parser)]
#[command(name = "rlogin")]
#[command(version = "1.0.0")]
#[command(author = "mustafaelrasheid")]
#[command(
    about = "login program that only uses yescript",
    long_about = None
)]
pub struct Cli {
    pub path: Option<String>,
    #[arg(long)]
    pub set_xdg_runtime_dir: bool,
}
