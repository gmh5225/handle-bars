mod cli;
mod pinfo;
mod enumhandles;
use std::process::exit;

fn main() {
    let (p_info, _verbose) = match cli::get_cli_args() {
        Ok(v) => {
            print!("[i] Found: {}", v.0);

            v
        }

        Err(e) => {
            let err: String = format!("{}", e);
            eprintln!("[!] Error Occured as: {}", err);
            exit(-1);
        }
    }; 

    enumhandles::find_handles(p_info.pid);
}