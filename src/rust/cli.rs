use clap::{
    value_parser,
    crate_authors, crate_description, crate_name, crate_version, Arg,
    Command,
    ArgAction::SetTrue
};
use std::process::exit;

// Enum to store the kind of indicator passed to the 
// program, i.e, if it is a program name or a process id
#[derive(Debug, Clone)]
pub enum Indicator {
    Name(String),
    Pid(u32)
}

// This struct contains the return value for parsed CLI args
#[derive(Debug, Clone)]
pub struct CliArgs{
    pub indicator: Indicator,
    pub verbose: bool
}

impl CliArgs {
    pub fn parse() -> CliArgs {
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
                .action(SetTrue)
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
        let verbose: bool = cli_args.get_flag("verbose").clone();

        if pname.is_some() {
            return CliArgs {
                indicator: Indicator::Name(pname.unwrap().clone()),
                verbose: verbose
            }
        }
        else if pid.is_some() {
            return CliArgs {
                indicator: Indicator::Pid(pid.unwrap()),
                verbose: verbose
            }
        }
        else {
            println!("[!] Invalid Usage\n[!] Use -h/--help flag for usage");
            exit(-1);
        }

    }
}