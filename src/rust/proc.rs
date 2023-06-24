use std::fmt;
use std::ffi::CString;
use std::error::Error;
use crate::cli::Indicator;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32};

// Struct to store String and PID
#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub name: String,
    pub pid: u32
}

// How to print things
impl fmt::Display for ProcInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})\n", self.name.as_str(), self.pid)
    }
}

impl ProcInfo {
    pub fn parse(indicator: &Indicator, verbose: bool) -> Result<ProcInfo, Box<dyn Error>> {
        let err = |msg: &str| {
            let _err_code = unsafe{GetLastError()};
            let _err = format!("{} {:#02x?}", msg, _err_code); 
            return _err;
        };

        if verbose {
            match indicator.clone() {
                Indicator::Name(name) => {
                    println!("[i] Looking for process:\t{}", name);
                },
                Indicator::Pid(pid)  => {
                    println!("[i] Looking for pid:\t{}", pid);
                }
            }
        }

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

        if verbose {
            println!("[!] Acquired Snapshot");
        }

        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

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

                match indicator {
                    Indicator::Name(name) => {
                        if exe_file_name.to_str().unwrap().to_ascii_lowercase() == name.clone().to_ascii_lowercase() {
                            unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
                            return Ok(
                                ProcInfo { 
                                    name: String::from(exe_file_name.to_str().unwrap()), 
                                    pid: entry.th32ProcessID, 
                                }
                            );
                        }
                    },
                    Indicator::Pid(pid) => {
                        if entry.th32ProcessID == *pid {
                            unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
                            return Ok(
                                ProcInfo { name: String::from(exe_file_name.to_str().unwrap()), pid: *pid }
                            );
                        }
                    }
                };

                if verbose {
                    println!("[i] Found Process: {} ({})", exe_file_name.to_str().unwrap(), entry.th32ProcessID);
                }

                if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }

        unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
        return Err(format!("No Process Found").into());
    }
}