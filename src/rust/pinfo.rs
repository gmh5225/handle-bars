use std::fmt;
use std::error::Error;
use std::ffi::CString;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub name: String,
    pub pid: u32,
}

impl fmt::Display for ProcInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})\n", self.name.as_str(), self.pid)
    }
}

impl ProcInfo {
    pub fn pid_from_proc_name(pname: String) -> Result<ProcInfo, Box<dyn Error>> {
        // Return error message with exit
        let err = |msg: &str| {
            let _err_code = unsafe{GetLastError()};
            let _err = format!("{} {:#02x?}", msg, _err_code); 
            return _err;
        };
        
        // Zero initialize struct
        let mut entry: PROCESSENTRY32;
        unsafe {
            entry = std::mem::zeroed();
        }

        // Get SnapShot
        let snapshot: HANDLE = unsafe { 
            CreateToolhelp32Snapshot(
                PROCESS_ALL_ACCESS, 0
            )
        };
        
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(err("Failed to get snapshot").into());
        }
        
        if cfg!(debug_assertions) {
            println!("[i] Acquired Snapshot");
        }

        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        if cfg!(debug_assertions) {
            println!("[i] Initialized PROCESSENTRY32 struct");
        }

        if unsafe { Process32First(snapshot, &mut entry) } != 0 {
            loop {
                let exe_file_name = unsafe { 
                    CString::from_vec_unchecked(
                        entry.szExeFile.iter()
                        .map(|&c| c as u8)
                        .take_while(|&c| c != 0)
                        .collect()
                    ) 
                };

                if cfg!(debug_assertions) {    
                    println!(
                        "[i] Found Process Executable: {} ({})", 
                        exe_file_name.to_str().unwrap(),
                        entry.th32ProcessID
                    );
                }

                if exe_file_name.to_str().unwrap().to_ascii_lowercase() == pname.to_ascii_lowercase() {
                    unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
                    return Ok(
                        ProcInfo { 
                            pid: entry.th32ProcessID, 
                            name: pname
                        }
                    );
                }

                if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }

        unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
        return Err(format!("No PID found for {}", pname).into());
    }

    pub fn proc_name_from_pid(pid: u32) -> Result<ProcInfo, Box<dyn Error>> {
        // Return error message with exit
        let err = |msg: &str| {
            let _err_code = unsafe{GetLastError()};
            let _err = format!("{} {:#02x?}", msg, _err_code); 
            return _err;
        };
        
        // Zero initialize struct
        let mut entry: PROCESSENTRY32;
        unsafe {
            entry = std::mem::zeroed();
        }

        // Get SnapShot
        let snapshot: HANDLE = unsafe { 
            CreateToolhelp32Snapshot(
                PROCESS_ALL_ACCESS, 0
            )
        };
        
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(err("Failed to get snapshot").into());
        }
        
        if cfg!(debug_assertions) {
            println!("[i] Acquired Snapshot");
        }

        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        if cfg!(debug_assertions) {
            println!("[i] Initialized PROCESSENTRY32 struct");
        }

        if unsafe { Process32First(snapshot, &mut entry) } != 0 {
            loop {
                let exe_file_name = unsafe { 
                    CString::from_vec_unchecked(
                        entry.szExeFile.iter()
                        .map(|&c| c as u8)
                        .take_while(|&c| c != 0)
                        .collect()
                    ) 
                };

                if cfg!(debug_assertions) {    
                    let _p_pid = entry.th32ProcessID.to_string();
                    println!(
                        "[i] Found PID: {} ({})", 
                        entry.th32ProcessID,
                        exe_file_name.to_str().unwrap(),
                    );
                }

                if entry.th32ProcessID == pid {
                    unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
                    return Ok(
                        ProcInfo { 
                            pid: pid, 
                            name: String::from(exe_file_name.to_str().unwrap())
                        }
                    );
                }

                if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }

        unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
        return Err(format!("No Process with pid {} found", pid).into());
    }

}