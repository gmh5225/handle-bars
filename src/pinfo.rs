use std::ffi::CString;
use std::error::Error;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;

// Struct to store PID and Process Name
pub struct ProcInfo {
    pub pid: u32,
    pub name: String
}

impl ProcInfo {
    pub fn pid_from_name(p_name: &str) -> Result<ProcInfo, Box<dyn Error>> {
        let mut entry: PROCESSENTRY32;

        // Return error message with exit
        let err = |msg: &str| {
            let _err_code = unsafe{GetLastError()};
            let _err = format!("{} {:#02x?}", msg, _err_code); 
            return _err;
        };

        // Get SnapShot
        let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(err("Failed to get snapshot").into());
        }
        if cfg!(debug_assertions) {
            println!("[i] Acquired Snapshot");
        }

        unsafe {
            entry = std::mem::zeroed();
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

                if exe_file_name.to_str().unwrap() == p_name {
                    if cfg!(debug_assertions) {
                        println!("[i] Process Found!");
                    }
                    unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
                    return Ok(
                        ProcInfo { 
                            pid: entry.th32ProcessID, 
                            name: String::from(p_name)
                        }
                    );
                }

                if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
        return Err(String::from("No PID found").into())
    }
}