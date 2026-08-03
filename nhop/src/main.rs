use std::env;
use std::io;
use std::process::ExitCode;

use nhop::cli;
use nhop_ipc::Paths;

const INTERNAL_EXIT: u8 = 1;

#[tokio::main]
async fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let mut borrowed = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        borrowed.push(argument.as_str());
    }
    let paths = match Paths::from_env() {
        Ok(paths) => paths,
        Err(failure) => {
            eprintln!("nhop: {failure}");
            return ExitCode::from(INTERNAL_EXIT);
        }
    };
    let exit = cli::run(&paths, &borrowed, &mut io::stdout(), &mut io::stderr()).await;
    ExitCode::from(exit.code())
}
