mod cli;
mod proc;
use std::process::exit;

#[link(name = ".\\out\\rustydump", kind = "static")]

extern "C" {
    fn fetch_handles(pid: u32, verbose: bool) -> i32;
}

fn main() {
    // Parse command line options
    let cli_args = cli::CliArgs::parse();
    let p_info = match proc::ProcInfo::parse(&(cli_args.indicator), cli_args.verbose) {
        Ok(v) => {
            print!("[i] Target Process: {}", v);
            v
        }
        Err(e) => {
            println!("[!] Error occured as {}", e);
            exit(-1);
        }
    };

    unsafe {
        fetch_handles(p_info.pid, cli_args.verbose);
    }
    
}