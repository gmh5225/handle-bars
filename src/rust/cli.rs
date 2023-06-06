use crate::pinfo::ProcInfo;
use colored::Colorize;
use clap::{
    value_parser,
    crate_authors, crate_description, crate_name, crate_version, Arg,
    Command,
};
use std::error::Error;
use std::process::exit;


pub fn get_cli_args() -> Result<ProcInfo, Box<dyn Error>> {
    let cli_args = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::new("process name")
                .long("name")
                .short('n')
                .help("Process Name to find")
                .conflicts_with("pid")
        )
        .arg(
            Arg::new("pid")
            .long("pid")
            .short('i')
            .help("Process ID to find")
            .value_parser(value_parser!(u32))
            .conflicts_with("process name")
        ).get_matches();
    
    let pname: Option<String> = cli_args.get_one::<String>("process name").cloned();
    let pid: Option<u32> = cli_args.get_one::<u32>("pid").cloned();
    
    // Check if name is specified
    if pname.is_some() {
        let name = pname.unwrap();
        if cfg!(debug_assertions) {
            println!("[{}] Looking for process: {}", "i".green(), name.cyan());
        }
        return ProcInfo::pid_from_proc_name(name);
    }

    // Check if pid is specified
    else if pid.is_some() {
        let ppid = pid.clone().unwrap();
        if cfg!(debug_assertions) {
            let _pid: String = pid.clone().unwrap().to_string();
            println!("[{}] Looking for pid:\t{}", "i".green(), _pid.cyan());
        }
        return ProcInfo::proc_name_from_pid(ppid);
    }

    else {
        println!(
            "[{}] Invalid Usage\n[!] Use {}/{} flag for usage",
            "!".red(),
            "-h".red().bold(),
            "--help".red().bold()
        );
        exit(-1);
    }

} 