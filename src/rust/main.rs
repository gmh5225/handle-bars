mod cli;
mod pinfo;
use colored::Colorize;
use std::process::exit;

fn main() {
    let _p_info = match cli::get_cli_args() {
        Ok(v) => {
            println!("[{}] Found: {}", "i".green(), v);
            v
        }

        Err(e) => {
            let err: String = format!("{}", e);
            eprintln!("[{}] Error Occured as: {}", "!".red(), err.red());
            exit(-1);
        }
    }; 
}