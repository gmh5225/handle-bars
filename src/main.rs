mod pinfo;
mod debug;

fn main() {
    let signature: u32;
    let version: u16;
    let impl_version: u16;
    let success: bool;

    let p_info = match pinfo::ProcInfo::pid_from_name("lsass.exe") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[!] Error occured as: {}", e);
            std::process::exit(-1);
        }
    };

    println!("[i] Found:\t{} ({})", p_info.name, p_info.pid);
}