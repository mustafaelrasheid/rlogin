use clap::Parser;

#[derive(Parser)]
#[command(name = "rlogin")]
#[command(version = "1.1.1")]
#[command(author = "mustafaelrasheid")]
#[command(
	about = "A simple login and authentication program.",
	long_about = None
)]
pub struct Cli {
	pub path: Option<String>,
	#[arg(long)]
	pub set_xdg_runtime_dir: bool,
}
