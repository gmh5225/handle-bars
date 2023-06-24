#include "enumhandles.h"

_NtQuerySystemInformation NtQuerySystemInformation;
_NtDuplicateObject NtDuplicateObject;
_NtQueryObject NtQueryObject;
_RtlInitUnicodeString RtlInitUnicodeString;
_RtlEqualUnicodeString RtlEqualUnicodeString;

void _dprintf(const char *format, ...) {
    if (VERBOSE) {
        char buffer[256];
        va_list args;
        va_start(args, format);
        vsprintf(buffer, format, args);
        printf(buffer);
        va_end(args);
    }
}

void _deprintf(const char *format, ...) {
    if (VERBOSE) {
        char buffer[256];
        va_list args;
        va_start(args, format);
        vsprintf(buffer, format, args);
        fprintf(stderr, buffer);
        va_end(args);
    }
}

PVOID get_lib_proc_addr(PSTR lib_name, PSTR proc_name) {
    _dprintf("[i] Resolving Address:\t %s(%s)\n", proc_name, lib_name);
    HMODULE hModule = GetModuleHandleA(lib_name);

    if (hModule == NULL)
    {
        _deprintf("[i] Got Handle to:\t%s\n", lib_name);
        return NULL;
    }

    PVOID addr = (PVOID)GetProcAddress(hModule, proc_name);
    if (addr == NULL)
    {
        _deprintf("[!] Failed to resolve:\t %s\n", proc_name);
        return NULL;
    }
    _dprintf("[i] Resolved Function:\t %s(0x%p)\n", proc_name, addr);
    return addr;
}

int resolve_functions() {
    NtQuerySystemInformation = get_lib_proc_addr("ntdll.dll", "NtQuerySystemInformation");
    NtDuplicateObject = get_lib_proc_addr("ntdll.dll", "NtDuplicateObject");
    NtQueryObject = get_lib_proc_addr("ntdll.dll", "NtQueryObject");
    RtlInitUnicodeString = get_lib_proc_addr("ntdll.dll", "RtlInitUnicodeString");
    RtlEqualUnicodeString = get_lib_proc_addr("ntdll.dll", "RtlEqualUnicodeString");
    if (RtlInitUnicodeString == NULL || RtlEqualUnicodeString == NULL || NtQuerySystemInformation == NULL || NtDuplicateObject == NULL || NtQueryObject == NULL) {
        return -1;
    }

    return 0;
}

// void read_file(HANDLE fileHandle) {
//     int MAX_LENGTH = 100;
//     char buffer[100] = {0};
//     DWORD bytesRead;
//     BOOL flag = ReadFile(fileHandle, buffer, MAX_LENGTH - 1, &bytesRead, NULL);
//     if (flag) {
//         if (bytesRead > 0){
//             buffer[bytesRead] = '\0';  // Null-terminate the buffer
//             printf("%s", buffer);
//         }
//         else {
//             printf("No Bytes Read\n");
//         }
//     }
//     CloseHandle(fileHandle);
// }

int fetch_handles(DWORD pid, BOOL verbose) {
    HANDLE hProcess;
    NTSTATUS status;
    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION hInfo;
    int c_pid = 0;
    UNICODE_STRING pProcess, pThread, pFile, pKey;
    VERBOSE = verbose;
    
    // Resolve Function Names
    if (resolve_functions() != 0) {
        _deprintf("[!] Failed to resolve Nt functions\n");
        return -1;
    }

    RtlInitUnicodeString(&pKey, L"Key");
    RtlInitUnicodeString(&pFile, L"File");
    RtlInitUnicodeString(&pThread, L"Thread");
    RtlInitUnicodeString(&pProcess, L"Process");

    hInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    if (hInfo == NULL) {
        fprintf(stderr, "[!] malloc() Failed! (0x%x)", GetLastError());
        return -1;
    }

    // NtQuerySystemInformation won't give us the correct buffer size,
    // so we guess by doubling the buffer size.
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
    while (1) {
        // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            hInfo,
            handleInfoSize,
            NULL);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            hInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(hInfo, handleInfoSize *= 2);
            if (hInfo == NULL) {
                fprintf(stderr, "[!] realloc() Failed! (0x%x)", GetLastError());
                return -1;
            }
        }
        // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
        else if (!NT_SUCCESS(status)) {
            fprintf(stderr, "[!] NtQuerySystemInformation() failed (0x%x)\n", status);
            free(hInfo);
            return -1;
        }
        else {
            break;
        }
    }

    _dprintf("[i] Total number of handles found:\t\t%d\n", hInfo->HandleCount);

    for (int i = 0; i < hInfo->HandleCount; i++) {
        SYSTEM_HANDLE handle = hInfo->Handles[i];

        // Check if this handle belongs to the PID the user specified.
        if (handle.ProcessId == pid)
            c_pid++;
    }

    printf("[i] Number of handles found for PID %d:\t%d\n", pid, c_pid);

    // Open Handle to Process ID
    hProcess = OpenProcess(
        PROCESS_DUP_HANDLE,     // Required to duplicate a handle
        FALSE,                  // Do not inherit handle
        pid);                   // Process ID 

    if (hProcess == NULL) {
        fprintf(stderr, "[!] OpenProcess() Failed! (0x%x)", GetLastError());
        return -1;
    }

    for (int i = 0; i < hInfo->HandleCount; i++) {
        ULONG returnLength;
        PVOID objectNameInfo;
        HANDLE dupHandle = NULL;
        UNICODE_STRING objectName;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        SYSTEM_HANDLE handle = hInfo->Handles[i];

        // Check if this handle belongs to the PID the user specified.
        if (handle.ProcessId != pid)
            continue;
        
        // https://github.com/tamentis/psutil/blob/7c1f4d1fe2fd523c23e25b2e8b4344158e9fdff7/psutil/arch/mswindows/process_handles.c#L178
        if((handle.GrantedAccess == 0x0012019f)
        || (handle.GrantedAccess == 0x001a019f)
        || (handle.GrantedAccess == 0x00120189)
        || (handle.GrantedAccess == 0x00100000)) {
            _dprintf("[?] Handle 0x%04x has unwanted access rights:\t0x%08x\n", handle.Handle, handle.GrantedAccess);
            continue;
        }

         // Duplicate the handle so we can query it.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
        status = NtDuplicateObject(
            hProcess,
            (void *)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0);

        if (!NT_SUCCESS(status)) {
            _deprintf("[?] Failed to Duplication Handle:\t0x%04x\n", handle.Handle);
            CloseHandle(dupHandle);
            continue;
        }

        // Query Object type
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (objectTypeInfo == NULL) {
            fprintf(stderr, "[!] Malloc() failed for OBJECT_TYPE_INFORMATION (0x%x)\n", GetLastError());
            free(hInfo);
            CloseHandle(dupHandle);
            CloseHandle(hProcess);
            return -1;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
        status = NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            _deprintf("[?] Object Type Query Failed");
            CloseHandle(dupHandle);
            free(objectTypeInfo);
            continue;
        }

        // Query the object name (unless it has an access of 0x0012019f, on which NtQueryObject could hang.
        objectNameInfo = malloc(0x1000);
        if (objectNameInfo == NULL) {
            fprintf(stderr, "[!] Malloc() failed for objectNameInfo (0x%x)\n", GetLastError());
            free(hInfo);
            free(objectTypeInfo);

            CloseHandle(dupHandle);
            CloseHandle(hProcess);
            return -1;
        }

        status = NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
        );

        if (!NT_SUCCESS(status)) {
            
            if (objectNameInfo == NULL) {
                _deprintf("[?] NtQueryObject() returned invalid handle\n");
                free(objectTypeInfo);
                CloseHandle(dupHandle);
                continue;
            }
           
            // Reallocate the buffer and try again.
            objectNameInfo = realloc(objectNameInfo, returnLength); 
            if (objectNameInfo == NULL) {
                fprintf(stderr, "[!] Realloc() failed for objectNameInfo (0x%x)\n", GetLastError());
                //free(hInfo);
                free(objectTypeInfo);

                CloseHandle(dupHandle);
                // CloseHandle(hProcess);
                // return -1;
                continue;
            }

            status = NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
            );

            if (!NT_SUCCESS(status)) {
                _deprintf("[?] Object Name Query Failed\n");
                free(objectTypeInfo);
                free(objectNameInfo);

                CloseHandle(dupHandle);
                continue;
            }
        }

        // Cast our buffer into an UNICODE_STRING.
        objectName = *(PUNICODE_STRING)objectNameInfo;

        // Operations with Handles
        if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pProcess, TRUE)) {
            // Do Something with a Process Handle
            if (objectName.Length) 
                printf("[i] Process Handle\t| 0x%04x | 0x%p | 0x%08x | %.*S\n", handle.Handle, handle.Object, handle.GrantedAccess, objectName.Length / 2, objectName.Buffer);
            else 
                printf("[i] Process Handle\t| 0x%04x | 0x%p | 0x%08x | [unnamed]\n", handle.Handle, handle.Object, handle.GrantedAccess);
        }
        else if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pThread, TRUE) ) {
            // Do something with a thread handle
            if (objectName.Length) 
                printf("[i] Thread Handle\t| 0x%04x | 0x%p | 0x%08x | %.*S\n", handle.Handle, handle.Object, handle.GrantedAccess, objectName.Length / 2, objectName.Buffer);
            else 
                printf("[i] Thread Handle\t| 0x%04x | 0x%p | 0x%08x | [unnamed]\n", handle.Handle, handle.Object, handle.GrantedAccess);
        }
        else if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pFile, TRUE) ) {
            // Do something with file handle
            if (objectName.Length) 
                printf("[i] File Handle\t\t| 0x%04x | 0x%p | 0x%08x | %.*S\n", handle.Handle, handle.Object, handle.GrantedAccess, objectName.Length / 2, objectName.Buffer);
            else 
                printf("[i] File Handle\t\t| 0x%04x | 0x%p | 0x%08x | [unnamed]\n", handle.Handle, handle.Object, handle.GrantedAccess);
            
            // HANDLE hFileNew;
            // DuplicateHandle(hProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &hFileNew, DUPLICATE_SAME_ACCESS, TRUE, DUPLICATE_SAME_ACCESS);
            // read_file(hFileNew);
        }

        else if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pKey, TRUE) ) {
            // Do Something with registry key
            if (objectName.Length) 
                printf("[i] Key Handle\t\t| 0x%04x | 0x%p | 0x%08x | %.*S\n", handle.Handle, handle.Object, handle.GrantedAccess, objectName.Length / 2, objectName.Buffer);
            else 
                printf("[i] Key Handle\t\t| 0x%04x | 0x%p | 0x%08x | [unnamed]\n", handle.Handle, handle.Object, handle.GrantedAccess);
        }
        else {
            if (objectName.Length) 
                printf("[i] Other Handle\t| 0x%04x | 0x%p | 0x%08x | %.*S : %.*S\n", handle.Handle, handle.Object, handle.GrantedAccess, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer, objectName.Length / 2, objectName.Buffer);
            else 
                printf("[i] Other Handle\t| 0x%04x | 0x%p | 0x%08x | %.*S : [unnamed]\n" ,handle.Handle, handle.Object, handle.GrantedAccess, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
        }

        free(objectNameInfo);
        free(objectTypeInfo);
        CloseHandle(dupHandle);
    }

    CloseHandle(hProcess);
    free(hInfo);
    return 0;
}