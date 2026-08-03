use std::env;
use std::process::ExitCode;

use nhop::daemon;
use nhop_ipc::Paths;

const USAGE_EXIT: u8 = 4;
const INTERNAL_EXIT: u8 = 1;

#[tokio::main]
async fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(command) = arguments.next() else {
        println!("nhop {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    };
    if command != "start" {
        eprintln!("nhop: unknown command {command:?}");
        return ExitCode::from(USAGE_EXIT);
    }
    let paths = match Paths::from_env() {
        Ok(paths) => paths,
        Err(failure) => {
            eprintln!("nhop: {failure}");
            return ExitCode::from(INTERNAL_EXIT);
        }
    };
    match daemon::run(&paths).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("nhop: {failure}");
            ExitCode::from(failure.exit_code())
        }
    }
}
