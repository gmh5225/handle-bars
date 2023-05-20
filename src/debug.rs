use winapi::um::winnt::HANDLE;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::{OpenProcessToken, GetCurrentProcess};
use winapi::um::winnt::{TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};

pub fn enable_dbg_priv() -> bool {
    let mut htoken: HANDLE = std::ptr::null_mut();
    let tkp: TOKEN_PRIVILEGES;
    let hcurrent: HANDLE;

    hcurrent = unsafe {GetCurrentProcess()};
    if hcurrent == INVALID_HANDLE_VALUE {
        eprintln!("[!] Failed to get handle to current process!");
        return false;
    }
    
    let status = unsafe {
        OpenProcessToken(
            hcurrent, 
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut htoken)
    };


    // HANDLE hToken;
	// TOKEN_PRIVILEGES tkp;
	// NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);

	// if (status != STATUS_SUCCESS) {
	// 	//Failed to open process token
	// 	return FALSE;
	// }

	// tkp.PrivilegeCount = 1;
	// tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// LPCWSTR lpwPriv = L"SeDebugPrivilege";
	// if (!LookupPrivilegeValueW(NULL, lpwPriv, &tkp.Privileges[0].Luid)) {
	// 	NtClose(hToken);
	// 	return FALSE;
	// }

	// status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	// if (status != STATUS_SUCCESS) {
	// 	//Failed to adjust process token
	// 	return FALSE;
	// }

	// NtClose(hToken);
	// return TRUE;
    true
}