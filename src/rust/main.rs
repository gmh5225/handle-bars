mod cli;
mod pinfo;
mod enumhandles;
use colored::Colorize;
use std::process::exit;

fn main() {
    let p_info = match cli::get_cli_args() {
        Ok(v) => {
            print!("[{}] Found: {}", "i".green(), v);
            v
        }

        Err(e) => {
            let err: String = format!("{}", e);
            eprintln!("[{}] Error Occured as: {}", "!".red(), err.red());
            exit(-1);
        }
    }; 

    enumhandles::find_handles(p_info.pid);
}