use crate::pinfo::ProcInfo;
use clap::{
    value_parser,
    crate_authors, crate_description, crate_name, crate_version, Arg,
    Command,
};
use std::error::Error;
use std::process::exit;


pub fn get_cli_args() -> Result<(ProcInfo, bool), Box<dyn Error>> {
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
            Arg::new("verbose")
            .long("verbose")
            .short('v')
            .help("Print verbose messages")
            .action(clap::ArgAction::SetTrue)
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
    let verbose: bool = cli_args.contains_id("verbose").clone();
    
    // Check if name is specified
    if pname.is_some() {
        let name = pname.unwrap();
        if cfg!(debug_assertions) {
            println!("[i] Looking for process: {}", name);
        }
        match ProcInfo::pid_from_proc_name(name) {
            Ok(v) => return Ok((v, verbose)),
            Err(e) => return Err(e),
        };
    }

    // Check if pid is specified
    else if pid.is_some() {
        let ppid = pid.clone().unwrap();
        if cfg!(debug_assertions) {
            let _pid: String = pid.clone().unwrap().to_string();
            println!("[i] Looking for pid:\t{}", _pid);
        }
        match ProcInfo::proc_name_from_pid(ppid) {
            Ok(v) => return Ok((v, verbose)),
            Err(e) => return Err(e),
        };
    }

    else {
        println!("[!] Invalid Usage\n[!] Use -h/--help flag for usage");
        exit(-1);
    }

} 